/**
 * Pluggable secret-scanner backend.
 *
 * Each scanner wraps an external binary (`gitleaks` or `trufflehog`) and
 * exposes the same minimal contract so the rest of the extension does
 * not have to know which one is in use.
 *
 * Common input shape:
 *   1. Caller stages the JSON-serialized request body to a private
 *      temp file and passes the path to {@link Scanner.scan}.
 *      TruffleHog and gitleaks v8 both require a real path (no
 *      `-` / `/dev/stdin`), so we standardize on the staged-file
 *      approach. The caller owns the file's lifecycle (create before,
 *      unlink after).
 *   2. The scanner spawns its binary with the args it needs, reads the
 *      report (file or stdout, depending on the tool) and returns a
 *      normalized {@link ScanResult}.
 *
 * Adding a new backend means writing one file in this directory and
 * registering it in `registry.ts`.
 */

/** A single secret finding emitted by a scanner. */
export interface SecretFinding {
  /** Stable rule/detector id (e.g. `aws-access-token`, `Github`, `PrivateKey`). */
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

/** Status of the scanner binary in the current environment. */
export type ScannerAvailability =
  | "available"
  | "missing"
  | "disabled" /* user turned scanning off */;

/** Scanner action as configured by the user. */
export type ScannerAction = "off" | "redact";

/** Identifier of a registered scanner backend. */
export type ScannerId = "gitleaks" | "trufflehog";

/** Options accepted by {@link Scanner.scan}. */
export interface ScanOptions {
  /** Hard timeout for the scan in milliseconds. */
  timeoutMs: number;
  /** Override for the availability probe (testing hook). */
  availabilityOverride?: ScannerAvailability;
}

/**
 * The contract every scanner backend must satisfy.
 *
 * Implementations are expected to be cheap to construct (a registry of
 * singletons is used) and side-effect-free until `scan()` is called.
 * The {@link Scanner.checkAvailability} method does a one-time probe
 * (e.g. `gitleaks --version` or `trufflehog --version`) and caches the
 * result for the lifetime of the process.
 */
export interface Scanner {
  /** Unique id of the backend (matches {@link ScannerId}). */
  readonly id: ScannerId;
  /** Human-friendly name shown in the output channel and status bar. */
  readonly displayName: string;
  /**
   * Resolve the absolute path or bare name of the binary that should
   * be spawned. Reads `process.env` and the relevant VS Code setting
   * each call so a config change takes effect immediately.
   */
  resolveBinary(): string;
  /**
   * Probe whether the binary is reachable and runnable. Cached after
   * the first successful call.
   */
  checkAvailability(): Promise<ScannerAvailability>;
  /**
   * Scan `text` for secrets and return a {@link ScanResult} with
   * `text` redacted in place. The caller is responsible for staging
   * `text` to disk and for cleaning up afterwards; the scanner only
   * spawns the binary and parses the result.
   */
  scan(text: string, options: ScanOptions): Promise<ScanResult>;
}
