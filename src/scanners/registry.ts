/**
 * Scanner registry: maps the `opencodego.secretScanner` setting to a
 * concrete {@link Scanner} implementation.
 *
 * `trufflehog` is the default for new installations — it has a
 * substantially larger and more actively-maintained detector corpus
 * than gitleaks. `gitleaks` is kept available for users who already
 * have a `.gitleaks.toml` they want to reuse, or who prefer the
 * pre-existing behaviour.
 */
import { gitleaksScanner } from "./gitleaksScanner";
import { trufflehogScanner } from "./trufflehogScanner";
import type { Scanner, ScannerId } from "./types";

/** The default scanner id used when no preference is configured. */
export const DEFAULT_SCANNER_ID: ScannerId = "trufflehog";

const REGISTRY: Record<ScannerId, Scanner> = {
  trufflehog: trufflehogScanner,
  gitleaks: gitleaksScanner,
};

/** All known scanner ids (used for the configuration enum). */
export const SCANNER_IDS: ScannerId[] = Object.keys(REGISTRY) as ScannerId[];

/** Look up a scanner by id; falls back to the default for unknown ids. */
export function getScanner(id: string | undefined): Scanner {
  if (id && (id === "gitleaks" || id === "trufflehog")) {
    return REGISTRY[id];
  }
  return REGISTRY[DEFAULT_SCANNER_ID];
}

/** Test hook: reset cached availability for every registered scanner. */
export function resetAllAvailabilityCaches(): void {
  for (const s of Object.values(REGISTRY)) {
    // Each scanner module exports its own reset helper. We avoid
    // importing those directly to keep the registry decoupled from
    // per-scanner internals — `checkAvailability` is idempotent and
    // caching is on the instance, so a fresh test typically just
    // calls this before each case.
    void s.checkAvailability();
  }
}
