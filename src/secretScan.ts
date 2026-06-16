/**
 * Secret scanning for outbound chat requests.
 *
 * Wraps the `gitleaks` CLI (https://github.com/gitleaks/gitleaks) and runs
 * it in `detect --no-git --stdin` mode against the serialized request body
 * before it is sent to the OpenCode Go API. Detected secrets are redacted
 * in-place (replaced with `[REDACTED:<rule-id>]`) so they never reach the
 * LLM provider.
 *
 * Design notes:
 * - gitleaks is a static analyzer with no MITM/proxy mode, so this is a
 *   pre-flight scan of the JSON body, not a network interceptor.
 * - The gitleaks binary is assumed to be on `$PATH` (configurable via
 *   `opencodego.gitleaksPath`). If it is missing the scanner degrades to a
 *   no-op and reports the status via `availability()`.
 * - All work is async, non-blocking, and bounded by a short timeout so a
 *   hung gitleaks process cannot stall chat.
 */
import { spawn } from "child_process";
import type { ChildProcess } from "child_process";
import { access, constants } from "fs/promises";
import { debugLog } from "./logging";

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
    if (binary.includes("/") || binary.includes("\\")) {
      try {
        await access(binary, constants.X_OK);
        _availabilityCache = "available";
        return "available";
      } catch {
        _availabilityCache = "missing";
        return "missing";
      }
    }
    // Bare name: try to spawn with `--version` and a short timeout.
    const ok = await canSpawn(binary, ["--version"], 1_000);
    _availabilityCache = ok ? "available" : "missing";
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
    return empty;
  }

  const binary = resolveGitleaksPath();
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const stdout = await runGitleaks(binary, text, timeoutMs);
  if (stdout.length === 0) {
    return empty;
  }

  const findings = parseGitleaksJson(stdout);
  if (findings.length === 0) {
    return empty;
  }

  const redacted = applyRedactions(text, findings);
  debugLog("SECRET-SCAN", {
    binary,
    findingCount: findings.length,
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
  return new Promise((resolve) => {
    let settled = false;
    let stdout = "";
    let stdoutBytes = 0;
    let truncated = false;
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
          "--stdin",
          "--report-format",
          "json",
          "--exit-code",
          "0", // never fail the request even if findings exist
          "--redact",
          "0", // we'll do our own redaction so we can label with rule id
          "-",
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

    // @types/node marks stdout/stderr/stdin on ChildProcess as nullable
    // for stdio: "inherit" callers. We forced stdio: ["pipe", ...] above
    // so they are guaranteed non-null at runtime.
    const stdoutStream = child.stdout;
    const stderrStream = child.stderr;
    const stdinStream = child.stdin;
    if (!stdoutStream || !stderrStream || !stdinStream) {
      finish("");
      return;
    }

    stdoutStream.setEncoding("utf8");
    stdoutStream.on("data", (chunk: string) => {
      if (truncated) return;
      stdoutBytes += Buffer.byteLength(chunk, "utf8");
      if (stdoutBytes > MAX_OUTPUT_BYTES) {
        truncated = true;
        return;
      }
      stdout += chunk;
    });
    stderrStream.setEncoding("utf8");
    stderrStream.on("data", () => {
      /* gitleaks writes findings to stdout, not stderr */
    });
    // Swallow stdin errors (e.g. EPIPE if gitleaks closes early on
    // pathological input). The write callback below handles the
    // error path; without an 'error' listener the process would
    // crash with an unhandled exception.
    stdinStream.on("error", () => finish(""));
    child.on("error", () => finish(""));
    child.on("close", () => {
      // gitleaks sometimes exits non-zero when findings exist; with
      // --exit-code 0 this should always be 0, but be defensive.
      finish(truncated ? "" : stdout);
    });

    timer = setTimeout(() => {
      try {
        child.kill("SIGKILL");
      } catch {
        /* ignore */
      }
      finish("");
    }, timeoutMs);
    timer.unref();

    try {
      stdinStream.write(input, "utf8", (err) => {
        if (err) {
          try {
            child.kill("SIGKILL");
          } catch {
            /* ignore */
          }
          finish("");
        }
      });
      stdinStream.end();
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
