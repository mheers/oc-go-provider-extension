/**
 * Output-channel wrapper for the outbound secret scanner.
 *
 * Exposes a single `vscode.OutputChannel` named
 *   "OpenCode Go: Secret Scan"
 * to the user (View → Output → OpenCode Go: Secret Scan) so that every
 * scan run produces visible progress in the IDE:
 *
 *   - binary resolution (which gitleaks was used, which path was tried)
 *   - per-request scan start (model, request byte count, timeout)
 *   - per-finding detail (rule id, redacted replacement, surrounding
 *     message role for context)
 *   - outcome (clean / redacted / scanner disabled / gitleaks missing)
 *   - any errors (spawn failures, parse errors, timeouts)
 *
 * The module is intentionally test-friendly: `setChannelForTests()`
 * lets unit tests inject a fake channel. In production the channel is
 * created lazily in `getChannel()`.
 */
import type { OutputChannel } from "vscode";
import * as vscode from "vscode";
import type { SecretFinding } from "./secretScan";

const CHANNEL_NAME = "OpenCode Go: Secret Scan";

let _channel: OutputChannel | undefined;

/**
 * Return the shared output channel, creating it on first use.
 *
 * Lazy creation keeps extension activation fast and lets unit tests
 * inject a mock via {@link setChannelForTests} without paying the cost
 * of `vscode.window.createOutputChannel`.
 */
export function getChannel(): OutputChannel {
  if (_channel === undefined) {
    const created = vscode.window.createOutputChannel(CHANNEL_NAME);
    _channel = created;
    return created;
  }
  return _channel;
}

/**
 * Test hook: replace the shared channel with a fake. Pass `undefined`
 * to reset to the lazy-init path.
 */
export function setChannelForTests(channel: OutputChannel | undefined): void {
  _channel = channel;
}

/** Dispose the channel (called from extension deactivate). */
export function disposeChannel(): void {
  if (_channel !== undefined) {
    _channel.dispose();
    _channel = undefined;
  }
}

function ts(): string {
  // Local time, second precision. Output channels render monospaced.
  return new Date().toLocaleTimeString();
}

function fmtBytes(n: number): string {
  if (n >= 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(2)} MB`;
  if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${n} B`;
}

function redactPreview(secret: string): string {
  if (secret.length <= 12) return "[short]";
  return `${secret.slice(0, 4)}…${secret.slice(-4)} (len=${secret.length})`;
}

/**
 * Read the currently configured scanner's display name from
 * `process.env`, mirroring the registry lookup in `secretScan.ts`.
 *
 * This is duplicated here (rather than imported from `secretScan.ts`)
 * to avoid a circular import: `secretScan.ts` imports this module for
 * logging, so we cannot import it back. The lookup is one env-var
 * read so the duplication is cheap; if `OPENCODEGO_SCANNER` is unset
 * we fall back to the same default the registry uses (`trufflehog`).
 */
function currentBackendName(): string {
  const raw = process.env["OPENCODEGO_SCANNER"];
  if (raw === "gitleaks" || raw === "trufflehog") return raw;
  return "trufflehog";
}

/**
 * A single, well-typed surface for emitting log lines. Every entrypoint
 * of the secret-scan pipeline funnels through one of these functions so
 * the output channel is the single source of truth for "what happened
 * last time the scanner ran".
 */
export const secretScanLog = {
  binaryResolved(binary: string, fromEnv: boolean): void {
    getChannel().appendLine(
      `[${ts()}] binary resolved: ${binary}` +
        (fromEnv
          ? " (from opencodego.gitleaksPath / opencodego.trufflehogPath)"
          : " (from $PATH)")
    );
  },

  scanStarted(input: {
    apiFormat: "openai" | "anthropic";
    bytes: number;
    timeoutMs: number;
    backend?: string;
    config?: string;
  }): void {
    const ch = getChannel();
    ch.appendLine("──────────────────────────────");
    const backendPart = input.backend ? `, backend=${input.backend}` : "";
    const configPart = input.config ? `, config=${input.config}` : "";
    ch.appendLine(
      `[${ts()}] ▶ scan started: api=${input.apiFormat}` +
        backendPart +
        configPart +
        `, body=${fmtBytes(input.bytes)}, timeout=${input.timeoutMs}ms`
    );
  },

  configFallback(configPath: string, bundledPath: string): void {
    getChannel().appendLine(
      `[${ts()}] ! invalid trufflehog config: ${configPath}; ` +
        `falling back to bundled default (${bundledPath})`
    );
  },

  scanClean(durationMs: number): void {
    getChannel().appendLine(
      `[${ts()}] ✓ clean — no findings (${durationMs.toFixed(1)}ms)`
    );
  },

  scanTimedOut(
    durationMs: number,
    timeoutMs: number,
    backend: string,
    partialBytes: number
  ): void {
    // Distinct from `scanClean` so the user can tell "actually
    // clean" from "scanner was killed before it could finish" —
    // the latter means secrets may have leaked through.
    getChannel().appendLine(
      `[${ts()}] ⏱ timed out — ${backend} scan aborted after ` +
        `${durationMs.toFixed(1)}ms (timeout=${timeoutMs}ms, ` +
        `${partialBytes} bytes received). ` +
        `Body may contain unredacted secrets.`
    );
  },

  scanRedacted(findings: SecretFinding[], durationMs: number): void {
    const ch = getChannel();
    ch.appendLine(
      `[${ts()}] ⚠ redacted ${findings.length} finding(s) (${durationMs.toFixed(
        1
      )}ms):`
    );
    findings.forEach((f, i) => {
      const file = f.file ?? "unknown";
      const location = typeof f.line === "number" ? `${file}:${f.line}` : file;
      ch.appendLine(
        `  ${i + 1}. rule=${f.ruleId}  redacted=${f.redacted}  ` +
          `file=${location}  ` +
          `secret=${redactPreview(f.secret)}`
      );
    });
  },

  scanDisabled(): void {
    getChannel().appendLine(
      `[${ts()}] ⊘ scan skipped — action=off (set opencodego.secretScan to "redact" to enable)`
    );
  },

  scanUnavailable(
    reason: "missing" | "timeout" | "spawn-error",
    detail?: string,
    binaryPath?: string
  ): void {
    const ch = getChannel();
    const backend = currentBackendName();
    const tried = binaryPath ? ` (tried: ${binaryPath})` : "";
    let reasonText: string;
    if (reason === "missing") {
      reasonText =
        `${backend} binary not found on $PATH${tried}. ` +
        `On Windows + VS Code Remote (WSL), the extension runs inside ` +
        `the WSL distro's non-interactive shell — install ${backend} ` +
        `inside the WSL distro, or set ` +
        `opencodego.${backend}Path to an absolute path.`;
    } else if (reason === "timeout") {
      reasonText = `${backend} scan timed out${tried}`;
    } else {
      reasonText = `${backend} process failed to start${tried}`;
    }
    ch.appendLine(`[${ts()}] ✗ scan unavailable — ${reasonText}`);
    if (detail) ch.appendLine(`    ${detail}`);
  },

  scanParseError(preview: string): void {
    getChannel().appendLine(
      `[${ts()}] ✗ could not parse ${currentBackendName()} output (re-using original body): ${preview}`
    );
  },

  /**
   * Reveal the channel in the Output view. Called by the
   * "Show Secret Scan Log" command.
   */
  reveal(): void {
    getChannel().show(true);
  },
};
