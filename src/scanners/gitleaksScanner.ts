/**
 * gitleaks backend (https://github.com/gitleaks/gitleaks).
 *
 * gitleaks v8.x requires both `--pipe` (read stdin) AND a real source
 * path on `-s`; without `-s` it scans 0 bytes regardless of the stdin
 * content. We therefore stage the JSON body to a temp file in a
 * private tmpdir and pass that path via `-s`. The JSON report is
 * written to a sibling file (`report.json`) and read back here.
 */
import { readFile } from "fs/promises";
import { join } from "path";
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
    let dir: string | undefined;
    let reportPath: string | undefined;
    try {
      const staged = await stageInput(text, "payload");
      dir = staged.dir;
      reportPath = join(dir, "report.json");
      // gitleaks v8 wants something on stdin to consume when `--pipe`
      // is set; the actual content is read from the source file.
      const stdout = await spawnScanner(
        binary,
        [
          "detect",
          "--no-git",
          "--no-banner",
          "--pipe",
          "-s",
          staged.path,
          "--report-format",
          "json",
          "--report-path",
          reportPath,
          "--exit-code",
          "0", // never fail the request even if findings exist
        ],
        { timeoutMs: options.timeoutMs, stdinInput: "\n" }
      );
      const duration = Date.now() - t0;

      // The JSON report lives on disk (not on stdout) because
      // gitleaks v8 opens the report file with `os.Create` and
      // `/dev/stdout` is not a valid target from a child process.
      let raw = stdout;
      if (raw.length === 0) {
        try {
          raw = await readFile(reportPath, "utf8");
        } catch (err) {
          debugLog("SECRET-SCAN-REPORT-READ-ERROR", {
            reportPath,
            error: err instanceof Error ? err.message : String(err),
          });
          return empty;
        }
      }
      const findings = parseGitleaksJson(raw);
      if (findings.length === 0) return empty;
      const redacted = applyRedactions(text, findings);
      debugLog("SECRET-SCAN", {
        backend: "gitleaks",
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

interface RawGitleaksFinding {
  RuleID?: string;
  Description?: string;
  Match?: string;
  Secret?: string;
  File?: string;
  Line?: number;
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
    });
  }
  return findings;
}
