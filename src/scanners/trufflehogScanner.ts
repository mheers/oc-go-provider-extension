/**
 * TruffleHog backend (https://github.com/trufflesecurity/trufflehog).
 *
 * TruffleHog's `filesystem` source does not accept `-` or `/dev/stdin`
 * — it walks a real path. We therefore stage the JSON body to a
 * temp file (same as gitleaks) and pass that path as the only
 * positional argument to `trufflehog filesystem`.
 *
 * Output is NDJSON (one JSON object per line on stdout) interleaved
 * with progress log lines starting with `{"level":` (when
 * `--log-level >= 0`). We pass `--log-level=-1` to silence those and
 * keep parsing trivial.
 *
 * Verification (trufflehog phoning home to confirm AWS/GitHub keys
 * are live) is OFF by default. The chat-request path must not make
 * network calls or block on them.
 */
import { debugLog } from "../logging";
import {
  applyRedactions,
  cleanupStage,
  spawnScanner,
  stageInput,
  whichProbe,
} from "./runner";
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
    let dir: string | undefined;
    try {
      const staged = await stageInput(text, "payload");
      dir = staged.dir;
      const stdout = await spawnScanner(
        binary,
        [
          "filesystem",
          "--no-verification",
          "--no-update",
          "--no-color",
          "--json",
          "--log-level=-1",
          "--filter-entropy=3.0",
          staged.path,
        ],
        { timeoutMs: options.timeoutMs }
      );
      const duration = Date.now() - t0;

      const findings = parseTrufflehogNdjson(stdout);
      if (findings.length === 0) return empty;
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
    } finally {
      await cleanupStage(dir);
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
