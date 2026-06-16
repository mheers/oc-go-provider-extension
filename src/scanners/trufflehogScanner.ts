/**
 * TruffleHog backend (https://github.com/trufflesecurity/trufflehog).
 *
 * We use the `trufflehog stdin` subcommand rather than `trufflehog
 * filesystem` for three reasons:
 *
 *  1. **No temp file.** `filesystem` requires a real on-disk path; we'd
 *     have to write the JSON body to a tmpdir, hand the path to
 *     trufflehog, then unlink. `stdin` reads from the process's stdin
 *     pipe, so the body never touches disk. This removes a small
 *     attack surface (a crashed process could otherwise leave a secret
 *     in `/tmp`) and a few IO syscalls per scan.
 *  2. **Same flags.** `trufflehog --help` shows the two subcommands
 *     accept the identical flag set, so the migration is a one-word
 *     change in `args`.
 *  3. **Performance is equivalent.** On a ~90 KB synthetic body the
 *     two paths both finish in ~1.3 s on a developer laptop. The
 *     scanner cost is dominated by the detector regex evaluation, not
 *     by disk staging.
 *
 * Output is NDJSON (one JSON object per line on stdout) interleaved
 * with progress log lines starting with `{"level":` (when
 * `--log-level >= 0`). We pass `--log-level=-1` to silence those and
 * keep parsing trivial.
 *
 * Verification is OFF by default. The chat-request path must not make
 * network calls or block on them.
 *
 * --- A note on `--results=unverified,unknown` -------------------------
 * TruffleHog classifies every detector hit into one of three buckets:
 *
 *   - `verified`    the secret was confirmed live (e.g. the GitHub
 *                   API accepted the token). Requires network.
 *   - `unverified`  the regex matched but verification either failed
 *                   or was skipped.
 *   - `unknown`     verification errored out (e.g. network timeout).
 *
 * The default for `--results` is the union of all three, BUT when
 * `--no-verification` is set, trufflehog drops the `verified` bucket
 * and — critically — also drops the `unverified` bucket, because
 * without verification there is no way to populate the `verified`
 * list. The end result is that every finding that would otherwise
 * trigger a redaction silently disappears from the JSON output. This
 * is the bug that allowed the `ghp_…` token in
 * `worst-secret-leaks-demo/cmd/server/main.go` to reach the LLM: the
 * scanner ran, found nothing, and reported a clean body.
 *
 * The fix is to explicitly add `--results=unverified,unknown` so that
 * unverified detections are still emitted as NDJSON. We do NOT include
 * `verified` because we always pass `--no-verification` and trufflehog
 * would otherwise complain.
 */
import { debugLog } from "../logging";
import { applyRedactions, spawnScanner, whichProbe } from "./runner";
import type {
  Scanner,
  ScanOptions,
  ScanResult,
  ScannerAvailability,
  SecretFinding,
} from "./types";

/** Resolve the trufflehog binary path. */
function resolveTrufflehogPath(): string {
  const configured = process.env["OPENCODEGO_TRUFFLEHOG_PATH"] ?? "";
  if (configured.trim().length > 0) {
    return configured.trim();
  }
  return "trufflehog";
}

let _availabilityCache: ScannerAvailability | undefined;

export function trufflehogResetAvailabilityCache(): void {
  _availabilityCache = undefined;
}

/**
 * Build the argv we hand to `trufflehog`. Centralised so the test
 * suite (and the log-line emitting `scanStarted`) can assert on the
 * exact set of flags.
 *
 * Notable flags:
 *   - `stdin`                       subcommand — read body from our stdin
 *   - `--no-verification`           do not phone home to confirm tokens
 *   - `--no-update`                 do not try to self-upgrade
 *   - `--no-color`                  no ANSI escape codes in the output
 *   - `--json`                      one finding per line as JSON
 *   - `--log-level=-1`              suppress the `{"level":...}` log lines
 *   - `--filter-entropy=3.0`        ignore very low-entropy unverified hits
 *   - `--results=unverified,unknown`   emit non-verified hits (see header)
 */
export function trufflehogBuildArgs(): string[] {
  return [
    "stdin",
    "--no-verification",
    "--no-update",
    "--no-color",
    "--json",
    "--log-level=-1",
    "--filter-entropy=3.0",
    "--results=unverified,unknown",
  ];
}

export const trufflehogScanner: Scanner = {
  id: "trufflehog",
  displayName: "trufflehog",

  resolveBinary(): string {
    return resolveTrufflehogPath();
  },

  async checkAvailability(): Promise<ScannerAvailability> {
    if (_availabilityCache !== undefined) return _availabilityCache;
    const ok = await whichProbe(resolveTrufflehogPath());
    _availabilityCache = ok ? "available" : "missing";
    return _availabilityCache;
  },

  async scan(text: string, options: ScanOptions): Promise<ScanResult> {
    const empty: ScanResult = { redacted: false, findings: [], text };
    if (!text) return empty;

    const avail =
      options.availabilityOverride ?? (await this.checkAvailability());
    if (avail !== "available") return empty;

    const binary = resolveTrufflehogPath();
    const t0 = Date.now();
    try {
      const stdout = await spawnScanner(
        binary,
        trufflehogBuildArgs(),
        { timeoutMs: options.timeoutMs, stdinInput: text }
      );
      const duration = Date.now() - t0;

      const findings = parseTrufflehogNdjson(stdout);
      if (findings.length === 0) {
        debugLog("SECRET-SCAN", {
          backend: "trufflehog",
          findingCount: 0,
          durationMs: duration,
        });
        return empty;
      }
      const redacted = applyRedactions(text, findings);
      debugLog("SECRET-SCAN", {
        backend: "trufflehog",
        findingCount: findings.length,
        durationMs: duration,
        rules: Array.from(new Set(findings.map((f) => f.ruleId))),
      });
      return { redacted: redacted !== text, findings, text: redacted };
    } catch (err) {
      debugLog("SECRET-SCAN-RUN-ERROR", {
        binary,
        error: err instanceof Error ? err.message : String(err),
      });
      return empty;
    }
  },
};

interface RawTrufflehogFinding {
  DetectorName?: string;
  DetectorType?: number;
  Raw?: string;
  Redacted?: string;
  Verified?: boolean;
  SourceMetadata?: {
    Data?: {
      Filesystem?: { file?: string; line?: number };
    };
  };
}

function parseTrufflehogNdjson(raw: string): SecretFinding[] {
  const findings: SecretFinding[] = [];
  if (!raw) return findings;
  // TruffleHog emits one JSON object per line. Walk the buffer line by
  // line and parse only the ones that look like a finding (i.e. they
  // have a `DetectorName` field). Anything else (log lines, banner)
  // is silently ignored.
  const lines = raw.split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed.startsWith("{")) continue;
    let parsed: RawTrufflehogFinding | undefined;
    try {
      parsed = JSON.parse(trimmed) as RawTrufflehogFinding;
    } catch {
      continue;
    }
    if (!parsed || typeof parsed.DetectorName !== "string") continue;
    const ruleId = parsed.DetectorName.trim();
    const secret = typeof parsed.Raw === "string" ? parsed.Raw : "";
    if (!ruleId || !secret) continue;
    findings.push({
      ruleId,
      secret,
      redacted: `[REDACTED:${ruleId}]`,
    });
  }
  return findings;
}
