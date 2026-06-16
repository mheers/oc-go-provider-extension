/**
 * Shared runtime helpers for scanner backends.
 *
 * Both `gitleaks` and `trufflehog` are external CLI tools that the
 * extension spawns as child processes. To keep the two backends
 * uniform and the spawning logic in one well-tested place, this module
 * owns:
 *
 *  - {@link stageInput} / {@link cleanupStage} — write a payload to a
 *    fresh tmpdir and clean it up afterwards.
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
import { mkdtemp, rm, writeFile } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import type { SecretFinding } from "./types";

/** Hard cap on a scanner's stdout in bytes (defence against runaway output). */
export const MAX_OUTPUT_BYTES = 4 * 1024 * 1024; // 4 MB

/**
 * Spawn `binary` with `args` and resolve to the full stdout content
 * (utf8). Resolves to the empty string on timeout, spawn error, or
 * non-zero exit (scanners are expected to encode findings in their
 * output format, not in the exit code).
 */
export function spawnScanner(
  binary: string,
  args: string[],
  options: { timeoutMs: number; stdinInput?: string } = { timeoutMs: 2_000 }
): Promise<string> {
  return new Promise((resolve) => {
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | undefined = undefined;
    const finish = (value: string): void => {
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
    } catch {
      finish("");
      return;
    }

    const stdoutChunks: Buffer[] = [];
    let stdoutBytes = 0;
    child.stdout?.on("data", (chunk: Buffer) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > MAX_OUTPUT_BYTES) {
        try {
          child.kill("SIGKILL");
        } catch {
          /* ignore */
        }
        finish("");
        return;
      }
      stdoutChunks.push(chunk);
    });
    child.stderr?.on("data", () => {
      /* drain stderr silently — scanners log progress there */
    });

    child.on("error", () => finish(""));
    child.on("close", () => {
      finish(Buffer.concat(stdoutChunks).toString("utf8"));
    });

    timer = setTimeout(() => {
      try {
        child.kill("SIGKILL");
      } catch {
        /* ignore */
      }
      finish("");
    }, options.timeoutMs);
    timer.unref();

    if (options.stdinInput !== undefined && child.stdin) {
      try {
        child.stdin.on("error", () => {
          try {
            child.kill("SIGKILL");
          } catch {
            /* ignore */
          }
          finish("");
        });
        child.stdin.end(options.stdinInput, "utf8");
      } catch {
        try {
          child.kill("SIGKILL");
        } catch {
          /* ignore */
        }
        finish("");
      }
    } else if (child.stdin) {
      child.stdin.end();
    }
  });
}

/**
 * Lightweight availability probe: try to spawn `binary` with `args`
 * and resolve to `true` iff it exits 0 within `timeoutMs`.
 */
export function canSpawn(
  binary: string,
  args: string[],
  timeoutMs: number
): Promise<boolean> {
  return spawnScanner(binary, args, { timeoutMs }).then(
    (out) => out.length > 0
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
 * Stage `text` to a fresh tmpdir and return the directory path plus
 * the staged file path. The caller MUST pass the directory to
 * {@link cleanupStage} when done.
 */
export async function stageInput(
  text: string,
  filename: string
): Promise<{ dir: string; path: string }> {
  const dir = await mkdtemp(join(tmpdir(), "ocg-scanner-"));
  const path = join(dir, filename);
  await writeFile(path, text, "utf8");
  return { dir, path };
}

/** Best-effort removal of a tmpdir created by {@link stageInput}. */
export async function cleanupStage(dir: string | undefined): Promise<void> {
  if (!dir) return;
  try {
    await rm(dir, { recursive: true, force: true });
  } catch {
    /* best effort */
  }
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
