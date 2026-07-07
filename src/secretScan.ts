/**
 * Public façade for the outbound secret scanner.
 *
 * This module is intentionally thin: it owns the user-facing API
 * (`scanAndRedact`, `availability`, `getConfigPath`, type re-exports)
 * and delegates to a registered backend (gitleaks or trufflehog)
 * selected by the `opencodego.secretScanner` setting.
 *
 * Why a façade:
 * - Adding a new backend (e.g. `detect-secrets`) is one new file in
 *   `src/scanners/` and one line in the registry — no caller has to
 *   change.
 * - The `opencodego.secretScan = "off" | "redact"` action is
 *   preserved for backward compatibility; "redact" means "use the
 *   configured scanner", "off" means short-circuit to the empty
 *   result.
 *
 * Input shape:
 *   Both gitleaks (`gitleaks stdin`) and trufflehog (`trufflehog
 *   stdin`) read the request body directly from the spawned child's
 *   stdin pipe. Neither writes the body to disk, so a crashed process
 *   cannot leave secrets behind in a temp directory.
 *
 * @see ./scanners/types.ts
 * @see ./scanners/registry.ts
 */
import {
  getScanner,
  DEFAULT_SCANNER_ID,
  SCANNER_IDS,
} from "./scanners/registry";
import { gitleaksResetAvailabilityCache } from "./scanners/gitleaksScanner";
import { trufflehogResetAvailabilityCache } from "./scanners/trufflehogScanner";
import type {
  ScanOptions,
  ScanResult,
  ScannerAvailability,
  ScannerId,
  SecretFinding,
} from "./scanners/types";
import { secretScanLog } from "./secretScanLog";

export type { ScanResult, ScannerAvailability, SecretFinding, ScannerId };
export { DEFAULT_SCANNER_ID, SCANNER_IDS };

/** Scanner action as configured by the user. */
export type ScannerAction = "off" | "redact";

/**
 * Default timeout for an individual scan.
 *
 * History: this used to be 2_000 ms. TruffleHog on a ~80 KB body
 * (e.g. a chat request with a large prompt prefix) routinely
 * exceeds 2 s on a cold WSL VM — the first run after the extension
 * activates is dominated by binary startup, detector-regex JIT, and
 * page-in time. The previous default caused a 2 s scan to silently
 * return an empty result, which the façade then reported as
 * "clean — no findings", sending the unredacted body to the LLM.
 * Bumped to 5 s so the realistic case finishes in-budget while a
 * truly-hung binary still cannot block the chat round-trip
 * indefinitely. The runner reports a distinct "timed out" log
 * line rather than a misleading "clean".
 */
const DEFAULT_TIMEOUT_MS = 5_000;

/**
 * Resolve which scanner backend should be used for the current
 * process, based on the `opencodego.secretScanner` setting. Unknown
 * values fall back to {@link DEFAULT_SCANNER_ID} (trufflehog).
 */
function resolveConfiguredScanner() {
  const configured = process.env["OPENCODEGO_SCANNER"] ?? "";
  return getScanner(configured || undefined);
}

/** Read the binary path for the currently configured scanner. */
export function getConfigPath(): string {
  return resolveConfiguredScanner().resolveBinary();
}

/** Read the display name for the currently configured scanner. */
export function getConfigName(): string {
  return resolveConfiguredScanner().displayName;
}

/**
 * Test/utility hook to reset the availability cache for both
 * registered scanners. Used by jest's `beforeEach` to keep tests
 * independent.
 */
export function _resetAvailabilityCache(): void {
  gitleaksResetAvailabilityCache();
  trufflehogResetAvailabilityCache();
}

/**
 * Probe whether the configured scanner is available. Cached per
 * scanner backend for the lifetime of the process.
 */
export async function availability(
  action: ScannerAction = "redact"
): Promise<ScannerAvailability> {
  if (action === "off") return "disabled";
  return resolveConfiguredScanner().checkAvailability();
}

/**
 * Scan a chunk of text (typically the JSON-serialized request body)
 * and return a `ScanResult` with secrets replaced by
 * `[REDACTED:<rule-id>]`.
 *
 * If scanning is disabled or the configured binary is missing, the
 * original text is returned unmodified with `redacted: false` and
 * `findings: []`.
 */
export async function scanAndRedact(
  text: string,
  options: {
    timeoutMs?: number;
    availabilityOverride?: ScannerAvailability;
    action?: ScannerAction;
    configPath?: string;
  } = {}
): Promise<ScanResult> {
  const empty: ScanResult = { redacted: false, findings: [], text };
  if (!text) return empty;

  const action: ScannerAction = options.action ?? "redact";
  if (action === "off") {
    secretScanLog.scanDisabled();
    return empty;
  }

  const opts: ScanOptions = {
    timeoutMs: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    availabilityOverride: options.availabilityOverride,
    configPath: options.configPath,
  };

  // Surface scanner-unavailability in the output channel. Without
  // this the user only ever sees the "scan started" header and then
  // silence, because the scanner backends return an empty result
  // (findings=[]) when the binary is missing — indistinguishable
  // from a clean run.
  const scanner = resolveConfiguredScanner();
  const avail =
    options.availabilityOverride ?? (await scanner.checkAvailability());
  if (avail !== "available") {
    // avail can only be "missing" here — "disabled" is handled above
    // via the action === "off" branch. Include the resolved path so
    // users on Windows + WSL Remote can see exactly which binary the
    // extension tried to spawn (and so confirm whether the override
    // setting took effect).
    secretScanLog.scanUnavailable(
      "missing",
      undefined,
      scanner.resolveBinary()
    );
    return empty;
  }

  const t0 = Date.now();
  const result = await scanner.scan(text, opts);
  const durationMs = Date.now() - t0;
  if (result.timedOut) {
    // The scanner was killed by its timeout. Any partial output
    // is suspect, so we return the original body unchanged. The
    // log line explicitly tells the user that secrets may have
    // leaked so they can re-send with a larger request, narrow
    // the prompt, or increase the timeout (future setting).
    secretScanLog.scanTimedOut(
      durationMs,
      opts.timeoutMs,
      scanner.id,
      // We don't have the partial-bytes count at this layer, so
      // report 0 — the per-scanner debug log already has the
      // accurate value.
      0
    );
    // Surface the timedOut flag to the caller as well so it can
    // decide whether to fail-closed in a future iteration (e.g.
    // an "opencodego.secretScanFailMode = block" setting). For
    // now, the body is returned unmodified — the LLM will see
    // the unredacted body, but the log channel makes this
    // visible to the user.
    return {
      redacted: false,
      findings: [],
      text: result.text,
      timedOut: true,
    };
  }
  if (result.findings.length === 0) {
    // Note: the per-scanner debugLog call already fired for clean
    // runs; emit the output-channel summary here so the user sees a
    // closing line for every scan-started header.
    secretScanLog.scanClean(durationMs);
    return empty;
  }
  secretScanLog.scanRedacted(result.findings, durationMs);
  return result;
}
