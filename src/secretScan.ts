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

/** Default timeout for an individual scan. */
const DEFAULT_TIMEOUT_MS = 2_000;

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
    // via the action === "off" branch.
    secretScanLog.scanUnavailable("missing");
    return empty;
  }

  const t0 = Date.now();
  const result = await scanner.scan(text, opts);
  const durationMs = Date.now() - t0;
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
