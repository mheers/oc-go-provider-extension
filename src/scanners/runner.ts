/**
 * Shared runtime helpers for scanner backends.
 *
 * Both `gitleaks` and `trufflehog` are external CLI tools that the
 * extension spawns as child processes. To keep the two backends
 * uniform and the spawning logic in one well-tested place, this module
 * owns:
 *
 *  - {@link spawnScanner} — generic, timeout-bounded child-process
 *    spawn with a structured error/cancellation story.
 *  - {@link applyRedactions} — longest-first string replacement,
 *    idempotent on overlapping matches.
 *  - {@link canSpawn} / {@link whichProbe} — availability probes used
 *    by both backends.
 */
import { spawn } from "child_process";
import type { ChildProcess } from "child_process";
import { access, constants } from "fs/promises";
import { debugLog } from "../logging";
import type { SecretFinding } from "./types";

/** Hard cap on a scanner's stdout in bytes (defence against runaway output). */
export const MAX_OUTPUT_BYTES = 4 * 1024 * 1024; // 4 MB

/**
 * Outcome of a single `spawnScanner` invocation. We resolve to this
 * (not a bare string) so callers can distinguish "binary ran and
 * produced no findings" from "binary was killed by the timeout and
 * any partial output is suspect". A 2 s timeout for a 80 KB
 * trufflehog body is realistic on a cold WSL VM, and reporting a
 * timed-out run as "clean" silently leaks the body to the LLM.
 */
export interface SpawnResult {
  /** UTF-8 decoded stdout, truncated to {@link MAX_OUTPUT_BYTES}. */
  stdout: string;
  /** True iff the kill-by-timeout fired before the child exited. */
  timedOut: boolean;
  /**
   * If a spawn error fired (async `error` event or synchronous
   * `spawn` throw), this carries the message for diagnostics.
   * Absent on a clean (or timed-out) run.
   */
  spawnError?: string;
  /**
   * The `code` field of the underlying `NodeJS.ErrnoException` if
   * the spawn errored (e.g. `"ENOENT"` for a missing binary,
   * `"EACCES"` for a non-executable file). Surface this in logs so
   * users on Windows + WSL Remote can see *why* their scanner was
   * not found.
   */
  spawnErrorCode?: string;
}

/**
 * Spawn `binary` with `args` and resolve to the full stdout content
 * (utf8) plus a `timedOut` flag. Resolves to `{ stdout: "",
 * timedOut: false }` on a clean early exit and to `{ stdout: <partial>,
 * timedOut: true }` if the timeout fires.
 */
export function spawnScanner(
  binary: string,
  args: string[],
  options: { timeoutMs: number; stdinInput?: string } = { timeoutMs: 2_000 }
): Promise<SpawnResult> {
  return new Promise((resolve) => {
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | undefined = undefined;
    let timedOut = false;
    const finish = (value: SpawnResult): void => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      resolve(value);
    };

    let child: ChildProcess;
    try {
      child = spawn(binary, args, {
        stdio: ["pipe", "pipe", "pipe"],
      });
    } catch (err) {
      // Synchronous spawn failure (typically `ENOENT` — the binary
      // is not on the resolved `PATH`). The most common cause on
      // Windows + VS Code Remote Server is that the scanner is
      // installed in the interactive shell's `PATH` on the host but
      // not in the non-interactive `PATH` of the WSL distro the
      // remote server is running in. We log to the debug log so the
      // user can see *which* binary was tried and *why* it failed.
      const code = (err as NodeJS.ErrnoException).code;
      debugLog("SCANNER-SPAWN-FAIL", {
        binary,
        args,
        code,
        error: err instanceof Error ? err.message : String(err),
      });
      finish({
        stdout: "",
        timedOut: false,
        spawnError: err instanceof Error ? err.message : String(err),
        spawnErrorCode: code,
      });
      return;
    }

    const stdoutChunks: Buffer[] = [];
    let stdoutBytes = 0;
    // Stderr is mostly noise (gitleaks/trufflehog progress lines),
    // but if the binary crashed early (missing shared library, bad
    // architecture, etc.) the only diagnostic lives here. Stash the
    // first 2 KB so we can surface it in the spawn-failure log.
    let stderrSample = "";
    child.stdout?.on("data", (chunk: Buffer) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > MAX_OUTPUT_BYTES) {
        try {
          child.kill("SIGKILL");
        } catch {
          /* ignore */
        }
        finish({ stdout: "", timedOut: false });
        return;
      }
      stdoutChunks.push(chunk);
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      const text = Buffer.isBuffer(chunk)
        ? chunk.toString("utf8")
        : String(chunk);
      if (text.length > 0) {
        stderrSample = (stderrSample + text).slice(0, 2048);
      }
    });

    child.on("error", (err) => {
      // Asynchronous spawn error (e.g. binary exists but cannot be
      // exec'd because of a library mismatch — common when copying a
      // binary from one distro to another, or from macOS to WSL).
      const code = (err as NodeJS.ErrnoException).code;
      debugLog("SCANNER-SPAWN-FAIL", {
        binary,
        args,
        code,
        error: err instanceof Error ? err.message : String(err),
        stderr: stderrSample,
      });
      finish({
        stdout: "",
        timedOut: false,
        spawnError: err instanceof Error ? err.message : String(err),
        spawnErrorCode: code,
      });
    });
    child.on("close", () => {
      finish({
        stdout: Buffer.concat(stdoutChunks).toString("utf8"),
        timedOut,
      });
    });

    timer = setTimeout(() => {
      // The scanner is still running but we have to abort the
      // request — chat round-trips cannot block on detection. The
      // `timedOut` flag propagates through the scanner module to
      // `ScanResult` so the caller can emit a distinct log line
      // (and, in the future, decide whether to fail-closed).
      //
      // We deliberately do NOT `unref()` the timer: in production
      // the real child process is an OS handle that keeps the
      // event loop alive, but in tests (and in any future caller
      // that uses a sync fake) the timer is the *only* thing
      // keeping the loop alive, and an unref'd timer can be
      // starved — manifesting as a silently-timed-out scan that
      // never resolves, which looks identical to a clean run
      // to the caller.
      //
      // We MUST call `finish` here, not just set the flag and
      // wait for `close`. On the real OS the SIGKILL'd child
      // emits `close` ~immediately, but in tests and in any
      // pathological case where the child is wedged in a way
      // that ignores SIGKILL, we still want the promise to
      // resolve so the request can proceed.
      timedOut = true;
      try {
        child.kill("SIGKILL");
      } catch {
        /* ignore */
      }
      finish({
        stdout: Buffer.concat(stdoutChunks).toString("utf8"),
        timedOut: true,
      });
    }, options.timeoutMs);

    if (options.stdinInput !== undefined && child.stdin) {
      try {
        child.stdin.on("error", () => {
          try {
            child.kill("SIGKILL");
          } catch {
            /* ignore */
          }
          finish({ stdout: "", timedOut: false });
        });
        child.stdin.end(options.stdinInput, "utf8");
      } catch {
        try {
          child.kill("SIGKILL");
        } catch {
          /* ignore */
        }
        finish({ stdout: "", timedOut: false });
      }
    } else if (child.stdin) {
      child.stdin.end();
    }
  });
}

/**
 * Lightweight availability probe: try to spawn `binary` with `args`
 * and resolve to `true` iff it exits with non-empty stdout within
 * `timeoutMs`. A timed-out or spawn-failed probe resolves to
 * `false`.
 */
export function canSpawn(
  binary: string,
  args: string[],
  timeoutMs: number
): Promise<boolean> {
  return spawnScanner(binary, args, { timeoutMs }).then(
    (out) => !out.timedOut && !out.spawnError && out.stdout.length > 0
  );
}

/**
 * Check whether `binary` is reachable. For paths containing a
 * separator we use `fs.access` with X_OK (cheap, no spawn). For bare
 * names we use a `--version` probe.
 */
export async function whichProbe(
  binary: string,
  versionTimeoutMs = 1_000
): Promise<boolean> {
  if (binary.includes("/") || binary.includes("\\")) {
    try {
      await access(binary, constants.X_OK);
      return true;
    } catch {
      return false;
    }
  }
  return canSpawn(binary, ["--version"], versionTimeoutMs);
}

/**
 * Apply the redaction set to `text`. Longest secrets are applied
 * first so an aws-access-token that is a substring of a longer match
 * does not shadow the longer one.
 */
export function applyRedactions(
  text: string,
  findings: SecretFinding[]
): string {
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
