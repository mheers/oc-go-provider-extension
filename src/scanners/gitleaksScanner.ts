/**
 * gitleaks backend (https://github.com/gitleaks/gitleaks).
 *
 * We use the `gitleaks stdin` subcommand to scan the request body
 * directly from the process's stdin pipe. This avoids writing the
 * body (which may contain secrets) to a temp file on disk — a
 * crashed process could otherwise leave secrets in `/tmp`. The JSON
 * report is emitted on stdout via `--report-path -`.
 *
 * gitleaks v8.x also has a `detect --pipe` mode, but that flag is
 * for piping git-log output, not arbitrary file content: without
 * `-s` it falls back to scanning the current directory (`.`), and
 * with `-s -` or `-s /dev/stdin` it scans 0 bytes. The dedicated
 * `stdin` subcommand is the only way to feed arbitrary content
 * without a real on-disk path.
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

/** Resolve the gitleaks binary path. */
function resolveGitleaksPath(): string {
  const configured = process.env["OPENCODEGO_GITLEAKS_PATH"] ?? "";
  if (configured.trim().length > 0) {
    return configured.trim();
  }
  return "gitleaks";
}

let _availabilityCache: ScannerAvailability | undefined;

export function gitleaksResetAvailabilityCache(): void {
  _availabilityCache = undefined;
}

/**
 * Build the argv we hand to `gitleaks stdin`. Centralised so the test
 * suite can assert on the exact set of flags.
 *
 * Notable flags:
 *   - `stdin`                         subcommand — read body from our stdin
 *   - `--no-banner`                   suppress the startup banner
 *   - `--report-format json`          emit findings as a JSON array
 *   - `--report-path -`               write the report to stdout (no temp file)
 *   - `--exit-code 0`                 never fail the request on findings
 *   - `--log-level error`             suppress info/warn log lines on stderr
 */
export function gitleaksBuildArgs(): string[] {
  return [
    "stdin",
    "--no-banner",
    "--report-format",
    "json",
    "--report-path",
    "-",
    "--exit-code",
    "0",
    "--log-level",
    "error",
  ];
}

export const gitleaksScanner: Scanner = {
  id: "gitleaks",
  displayName: "gitleaks",

  resolveBinary(): string {
    return resolveGitleaksPath();
  },

  async checkAvailability(): Promise<ScannerAvailability> {
    if (_availabilityCache !== undefined) return _availabilityCache;
    const ok = await whichProbe(resolveGitleaksPath());
    _availabilityCache = ok ? "available" : "missing";
    return _availabilityCache;
  },

  async scan(text: string, options: ScanOptions): Promise<ScanResult> {
    const empty: ScanResult = { redacted: false, findings: [], text };
    if (!text) return empty;

    const avail =
      options.availabilityOverride ?? (await this.checkAvailability());
    if (avail !== "available") return empty;

    const binary = resolveGitleaksPath();
    const t0 = Date.now();
    try {
      const { stdout, timedOut } = await spawnScanner(
        binary,
        gitleaksBuildArgs(),
        {
          timeoutMs: options.timeoutMs,
          stdinInput: text,
        }
      );
      const duration = Date.now() - t0;

      if (timedOut) {
        // The scanner was killed by its timeout. Any output it had
        // already produced is partial — secrets could be in the
        // remaining bytes that never made it to stdout. We must NOT
        // return a partial redaction: that would be worse than
        // either no scan (caller decides policy) or a full scan
        // (caller re-runs with a longer budget). Signal the timeout
        // up to the façade so it can emit a distinct log line.
        debugLog("SECRET-SCAN-TIMEOUT", {
          backend: "gitleaks",
          durationMs: duration,
          timeoutMs: options.timeoutMs,
          partialBytes: stdout.length,
        });
        return { redacted: false, findings: [], text, timedOut: true };
      }

      const findings = parseGitleaksJson(stdout);
      if (findings.length === 0) {
        debugLog("SECRET-SCAN", {
          backend: "gitleaks",
          findingCount: 0,
          durationMs: duration,
        });
        return empty;
      }
      const redacted = applyRedactions(text, findings);
      debugLog("SECRET-SCAN", {
        backend: "gitleaks",
        findingCount: findings.length,
        durationMs: duration,
        rules: Array.from(new Set(findings.map((f) => f.ruleId))),
        locations: findings.map((f) => ({
          ruleId: f.ruleId,
          file: f.file,
          line: f.line,
        })),
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

interface RawGitleaksFinding {
  RuleID?: string;
  Description?: string;
  Match?: string;
  Secret?: string;
  File?: string;
  StartLine?: number;
}

function parseGitleaksJson(raw: string): SecretFinding[] {
  const findings: SecretFinding[] = [];
  const trimmed = raw.trim();
  if (!trimmed) return findings;

  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    // Some gitleaks versions emit a JSON array with a trailing newline
    // followed by a status line; try the first JSON-ish prefix.
    const arrayEnd = trimmed.lastIndexOf("]");
    const objectEnd = trimmed.lastIndexOf("}");
    const cut = Math.max(arrayEnd, objectEnd);
    if (cut <= 0) return findings;
    try {
      parsed = JSON.parse(trimmed.slice(0, cut + 1));
    } catch {
      return findings;
    }
  }

  const items: RawGitleaksFinding[] = Array.isArray(parsed)
    ? (parsed as RawGitleaksFinding[])
    : parsed
      ? [parsed as RawGitleaksFinding]
      : [];
  for (const item of items) {
    const ruleId = typeof item.RuleID === "string" ? item.RuleID : "";
    const secret =
      typeof item.Secret === "string"
        ? item.Secret
        : typeof item.Match === "string"
          ? item.Match
          : "";
    if (!ruleId || !secret) continue;
    findings.push({
      ruleId,
      secret,
      redacted: `[REDACTED:${ruleId}]`,
      // In `stdin` mode gitleaks leaves `File` empty (there is no
      // on-disk source); `StartLine` is the 1-indexed line within
      // the piped input.
      file:
        typeof item.File === "string" && item.File.length > 0
          ? item.File
          : undefined,
      line:
        typeof item.StartLine === "number" && Number.isFinite(item.StartLine)
          ? item.StartLine
          : undefined,
    });
  }
  return findings;
}
