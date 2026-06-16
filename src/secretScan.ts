/**
 * Secret scanning for outbound chat requests.
 *
 * Wraps the `gitleaks` CLI (https://github.com/gitleaks/gitleaks) and runs
 * it in `detect --no-git --pipe -s <staged-file>` mode against the
 * serialized request body before it is sent to the OpenCode Go API.
 * Detected secrets are redacted in-place (replaced with
 * `[REDACTED:<rule-id>]`) so they never reach the LLM provider.
 *
 * Design notes:
 * - gitleaks is a static analyzer with no MITM/proxy mode, so this is a
 *   pre-flight scan of the JSON body, not a network interceptor.
 * - gitleaks v8.30.x requires both `--pipe` (read stdin) AND a real
 *   source path on `-s`; without `-s` it scans 0 bytes regardless of
 *   the stdin content. We therefore stage the JSON body to a temp
 *   file in a private tmpdir and pass that path via `-s`.
 * - The gitleaks binary is assumed to be on `$PATH` (configurable via
 *   `opencodego.gitleaksPath`). If it is missing the scanner degrades
 *   to a no-op and reports the status via `availability()`.
 * - All work is async, non-blocking, and bounded by a short timeout so
 *   a hung gitleaks process cannot stall chat.
 */
import { spawn } from "child_process";
import type { ChildProcess } from "child_process";
import { access, constants } from "fs/promises";
import { mkdtemp, readFile, rm } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { debugLog } from "./logging";
import { secretScanLog } from "./secretScanLog";

/** A single secret finding emitted by gitleaks. */
export interface SecretFinding {
  /** gitleaks rule id (e.g. `aws-access-token`). */
  ruleId: string;
  /** The exact secret string as it appeared in the input. */
  secret: string;
  /** Redacted replacement applied to the input. */
  redacted: string;
}

/** Result of scanning a chunk of text. */
export interface ScanResult {
  /** True if at least one finding was redacted. */
  redacted: boolean;
  /** All findings, in order of detection. */
  findings: SecretFinding[];
  /** The text with secrets replaced by their `redacted` form. */
  text: string;
}

/** Status of the gitleaks binary in the current environment. */
export type ScannerAvailability =
  | "available"
  | "missing"
  | "disabled" /* user turned scanning off */;

/** Scanner action as configured by the user. */
export type ScannerAction = "off" | "redact";

const DEFAULT_TIMEOUT_MS = 2_000;
const MAX_OUTPUT_BYTES = 4 * 1024 * 1024; // 4 MB cap on gitleaks output

/**
 * Resolve the path to the gitleaks binary.
 *
 * Honors `opencodego.gitleaksPath` if set and non-empty, otherwise
 * defaults to `gitleaks` (resolved via $PATH).
 */
function resolveGitleaksPath(): string {
  const configured = process.env["OPENCODEGO_GITLEAKS_PATH"] ?? "";
  if (configured.trim().length > 0) {
    return configured.trim();
  }
  return "gitleaks";
}

/**
 * Lightweight check that the binary is reachable.
 *
 * - For absolute paths we use `fs.access` with X_OK.
 * - For bare names we use `which`-style resolution by attempting a
 *   non-blocking spawn; the result is cached for the lifetime of the
 *   process.
 */
let _availabilityCache: ScannerAvailability | undefined;
let _availabilityPromise: Promise<ScannerAvailability> | undefined;

export function getConfigPath(): string {
  return resolveGitleaksPath();
}

export async function availability(
  action: ScannerAction = "redact"
): Promise<ScannerAvailability> {
  if (action === "off") return "disabled";
  if (_availabilityCache !== undefined) return _availabilityCache;
  if (_availabilityPromise !== undefined) return _availabilityPromise;

  _availabilityPromise = (async () => {
    const binary = resolveGitleaksPath();
    const fromEnv =
      (process.env["OPENCODEGO_GITLEAKS_PATH"] ?? "").trim().length > 0;
    if (binary.includes("/") || binary.includes("\\")) {
      try {
        await access(binary, constants.X_OK);
        _availabilityCache = "available";
        secretScanLog.binaryResolved(binary, fromEnv);
        return "available";
      } catch {
        _availabilityCache = "missing";
        secretScanLog.binaryResolved(binary, fromEnv);
        return "missing";
      }
    }
    // Bare name: try to spawn with `--version` and a short timeout.
    const ok = await canSpawn(binary, ["--version"], 1_000);
    _availabilityCache = ok ? "available" : "missing";
    secretScanLog.binaryResolved(binary, fromEnv);
    return _availabilityCache;
  })();
  return _availabilityPromise;
}

/** Test/utility hook to reset the availability cache between runs. */
export function _resetAvailabilityCache(): void {
  _availabilityCache = undefined;
  _availabilityPromise = undefined;
}

function canSpawn(
  binary: string,
  args: string[],
  timeoutMs: number
): Promise<boolean> {
  return new Promise((resolve) => {
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const child = spawn(binary, args, { stdio: "ignore" });
      child.on("error", () => {
        if (settled) return;
        settled = true;
        if (timer) clearTimeout(timer);
        resolve(false);
      });
      child.on("close", (code) => {
        if (settled) return;
        settled = true;
        if (timer) clearTimeout(timer);
        resolve(code === 0);
      });
      timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        try {
          child.kill("SIGKILL");
        } catch {
          /* ignore */
        }
        resolve(false);
      }, timeoutMs);
      timer.unref();
    } catch {
      if (timer) clearTimeout(timer);
      resolve(false);
    }
  });
}

/**
 * Scan a chunk of text (typically the JSON-serialized request body) and
 * return a `ScanResult` with secrets replaced by `[REDACTED:<rule-id>]`.
 *
 * If gitleaks is unavailable, the original text is returned unmodified
 * with `redacted: false` and `findings: []`. Callers should consult
 * `availability()` separately if they want to surface the status.
 */
export async function scanAndRedact(
  text: string,
  options: {
    timeoutMs?: number;
    availabilityOverride?: ScannerAvailability;
  } = {}
): Promise<ScanResult> {
  const empty: ScanResult = { redacted: false, findings: [], text };
  if (!text) return empty;

  // Skip spawning if the binary is not available. This keeps the request
  // path fast and avoids EPIPE noise on machines without gitleaks.
  const avail = options.availabilityOverride ?? (await availability());
  if (avail !== "available") {
    // Either user disabled scanning (`disabled`) or the binary is not
    // installed (`missing`). Both reduce to the same no-op behavior; we
    // log once for visibility in the output channel.
    secretScanLog.scanUnavailable("missing");
    return empty;
  }

  const binary = resolveGitleaksPath();
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const t0 = Date.now();
  const stdout = await runGitleaks(binary, text, timeoutMs);
  const duration = Date.now() - t0;
  if (stdout.length === 0) {
    return empty;
  }

  const findings = parseGitleaksJson(stdout);
  if (findings.length === 0) {
    secretScanLog.scanClean(duration);
    return empty;
  }

  const redacted = applyRedactions(text, findings);
  secretScanLog.scanRedacted(findings, duration);
  debugLog("SECRET-SCAN", {
    binary,
    findingCount: findings.length,
    durationMs: duration,
    rules: Array.from(new Set(findings.map((f) => f.ruleId))),
  });
  return { redacted: redacted !== text, findings, text: redacted };
}

interface RawGitleaksFinding {
  RuleID?: string;
  Description?: string;
  Match?: string;
  Secret?: string;
  File?: string;
  Line?: number;
  // Some versions emit "Match" only and not "Secret"
}

function runGitleaks(
  binary: string,
  input: string,
  timeoutMs: number
): Promise<string> {
  // gitleaks v8 requires both `--pipe` (to read stdin) AND `-s` (a
  // real file path) — without a source path it scans 0 bytes and
  // reports "no leaks found" even when the stdin is full of secrets.
  // We therefore stage the input to a temp file in a fresh tmpdir
  // and pass that path via `-s`. The JSON report is written to a
  // sibling file (`report.json`) and read back here. The tmpdir is
  // removed in the finally block; on Linux it's just `rm -rf` so the
  // cost is negligible.
  return (async () => {
    let staged: string | undefined;
    let dir: string | undefined;
    let reportPath: string | undefined;
    try {
      dir = await mkdtemp(join(tmpdir(), "ocg-scanner-"));
      staged = join(dir, "payload");
      reportPath = join(dir, "report.json");
      // gitleaks' default reporter writes the report file synchronously
      // on close(); forking from here is fine because we never reuse
      // the same path within the same mkdtemp.
      const { writeFile: writeFileSync } = await import("fs/promises");
      await writeFileSync(staged, input, "utf8");

      const json = await spawnGitleaks(
        binary,
        staged,
        reportPath,
        timeoutMs
      );
      return json;
    } catch (err) {
      debugLog("SECRET-SCAN-RUN-ERROR", {
        binary,
        error: err instanceof Error ? err.message : String(err),
      });
      return "";
    } finally {
      if (dir) {
        try {
          await rm(dir, { recursive: true, force: true });
        } catch {
          /* best effort cleanup */
        }
      }
    }
  })();
}

function spawnGitleaks(
  binary: string,
  sourcePath: string,
  reportPath: string,
  timeoutMs: number
): Promise<string> {
  return new Promise((resolve) => {
    let settled = false;
    let timedOut = false;
    let timer: ReturnType<typeof setTimeout> | undefined = undefined;

    const finish = (value: string): void => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      resolve(value);
    };

    let child: ChildProcess;
    try {
      child = spawn(
        binary,
        [
          "detect",
          "--no-git",
          "--no-banner",
          "--pipe",
          "-s",
          sourcePath,
          "--report-format",
          "json",
          "--report-path",
          reportPath,
          "--exit-code",
          "0", // never fail the request even if findings exist
        ],
        { stdio: ["pipe", "pipe", "pipe"] }
      );
    } catch (err) {
      debugLog("SECRET-SCAN-SPAWN-ERROR", {
        binary,
        error: err instanceof Error ? err.message : String(err),
      });
      finish("");
      return;
    }

    const stdinStream = child.stdin;
    if (!stdinStream) {
      finish("");
      return;
    }
    // Swallow stdin errors. We don't use stdin for input (the source
    // file is the source of truth) but gitleaks still wants something
    // on stdin to consume when `--pipe` is set, so we send an empty
    // newline and close.
    stdinStream.on("error", () => {
      try {
        child.kill("SIGKILL");
      } catch {
        /* ignore */
      }
      finish("");
    });
    child.on("error", () => finish(""));
    child.on("close", () => {
      if (timedOut) {
        secretScanLog.scanUnavailable("timeout", `after ${timeoutMs}ms`);
        finish("");
        return;
      }
      // The JSON report lives on disk (not on stdout) because
      // gitleaks v8 opens the report file with `os.Create` and
      // `/dev/stdout` is not a valid target from a child process.
      // Read it back; if it's empty or missing, return an empty
      // string so the caller logs "no findings".
      void (async () => {
        try {
          const raw = await readFile(reportPath, "utf8");
          // gitleaks may emit a JSON array (`[]` or `[ {...} ]`) or
          // sometimes a single object; both are fine for our parser.
          if (raw.length > MAX_OUTPUT_BYTES) {
            debugLog("SECRET-SCAN-OUTPUT-TRUNCATED", {
              bytes: raw.length,
              max: MAX_OUTPUT_BYTES,
            });
            finish("");
            return;
          }
          finish(raw);
        } catch (err) {
          debugLog("SECRET-SCAN-REPORT-READ-ERROR", {
            reportPath,
            error: err instanceof Error ? err.message : String(err),
          });
          finish("");
        }
      })();
    });

    timer = setTimeout(() => {
      timedOut = true;
      try {
        child.kill("SIGKILL");
      } catch {
        /* ignore */
      }
    }, timeoutMs);
    timer.unref();

    // Feed stdin so gitleaks doesn't hang waiting for EOF on the
    // pipe. The actual content is read from the source file.
    try {
      stdinStream.write("\n", "utf8", () => {
        try {
          stdinStream.end();
        } catch {
          /* ignore */
        }
      });
    } catch {
      try {
        child.kill("SIGKILL");
      } catch {
        /* ignore */
      }
      finish("");
    }
  });
}

function parseGitleaksJson(raw: string): SecretFinding[] {
  const findings: SecretFinding[] = [];
  const trimmed = raw.trim();
  if (!trimmed) return findings;

  // gitleaks may emit a single JSON object (one finding) or an array of
  // findings; tolerate both.
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

function applyRedactions(text: string, findings: SecretFinding[]): string {
  // Apply longest secrets first to avoid prefix collisions (e.g. an
  // aws-access-token being a substring of a longer match).
  const ordered = [...findings].sort(
    (a, b) => b.secret.length - a.secret.length
  );
  let out = text;
  const seen = new Set<string>();
  for (const f of ordered) {
    if (seen.has(f.secret)) continue;
    seen.add(f.secret);
    if (!f.secret) continue;
    out = out.split(f.secret).join(f.redacted);
  }
  return out;
}
