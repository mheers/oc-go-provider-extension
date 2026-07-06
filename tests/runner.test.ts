/// <reference types="jest" />

import { EventEmitter } from "events";
import { Readable, Writable } from "stream";

import { spawnScanner, MAX_OUTPUT_BYTES } from "../src/scanners/runner";

/**
 * Focused tests for {@link spawnScanner}'s timeout + spawn-failure
 * paths. The other scanner test files exercise the happy path
 * (stdin → stdout → close) via the same fake-child pattern; here we
 * drive the negative paths directly so the contract is pinned.
 *
 * Key contract under test:
 *   - When the kill-by-timeout fires before the child exits, the
 *     returned `SpawnResult` MUST have `timedOut: true` and the
 *     partial stdout (anything already received) preserved.
 *   - A subsequent `close` event must NOT clobber the timed-out
 *     resolution: the runner's `settled` guard resolves exactly
 *     once, and the first resolver (the timeout) wins.
 *   - A `SpawnResult` from a spawn error (ENOENT etc.) must
 *     surface `spawnError` and `spawnErrorCode` so the caller can
 *     log a useful diagnostic.
 */
class FakeChildProcess extends EventEmitter {
  public stdin: Writable;
  public stdout: Readable;
  public stderr: Readable;
  public killed = false;
  public responded = false;
  /** When true, the child stays open until `flushClose()` is called. */
  public holdOpen: boolean;
  constructor(holdOpen: boolean) {
    super();
    this.holdOpen = holdOpen;
    this.stdin = new Writable({
      write(_chunk, _enc, cb) {
        cb();
      },
    });
    this.stdout = new Readable({ read() {} });
    this.stderr = new Readable({ read() {} });
  }
  kill(): boolean {
    this.killed = true;
    return true;
  }
  /** Manually close (used by the timeout test to simulate the post-kill close). */
  flushClose(exitCode: number | null = 0): void {
    if (this.responded) return;
    this.responded = true;
    (this.stdout as Readable).push(null);
    (this.stderr as Readable).push(null);
    this.emit("close", exitCode);
  }
}

let spawned: FakeChildProcess[] = [];

jest.mock("child_process", () => {
  const real = jest.requireActual("child_process");
  return {
    ...real,
    spawn: jest.fn((_binary: string, _args: string[], _opts: unknown) => {
      const holdOpen =
        (global as { __HOLD_OPEN__?: boolean }).__HOLD_OPEN__ === true;
      const child = new FakeChildProcess(holdOpen);
      spawned.push(child);
      // Emit an `error` event immediately if requested. Used to
      // exercise the async spawn-error path.
      if ((global as { __SPAWN_ERROR__?: string }).__SPAWN_ERROR__) {
        const err = new Error(
          (global as { __SPAWN_ERROR__?: string }).__SPAWN_ERROR__!
        ) as NodeJS.ErrnoException;
        err.code = (
          global as { __SPAWN_ERROR_CODE__?: string }
        ).__SPAWN_ERROR_CODE__;
        queueMicrotask(() => child.emit("error", err));
      }
      if (!holdOpen) {
        // Mimic the existing scanner-test pattern: the child closes
        // as soon as its stdin is finished. We push null to stdout
        // synchronously and emit close.
        const send = (): void => {
          if (child.responded) return;
          child.responded = true;
          (child.stdout as Readable).push(null);
          (child.stderr as Readable).push(null);
          child.emit("close", 0);
        };
        child.stdin.on("finish", send);
        child.stdin.on("close", send);
      }
      return child;
    }),
  };
});

jest.mock("../src/logging", () => ({
  debugLog: jest.fn(),
}));

beforeEach(() => {
  spawned = [];
  jest.clearAllMocks();
  delete (global as { __HOLD_OPEN__?: boolean }).__HOLD_OPEN__;
  delete (global as { __SPAWN_ERROR__?: string }).__SPAWN_ERROR__;
  delete (global as { __SPAWN_ERROR_CODE__?: string }).__SPAWN_ERROR_CODE__;
});

describe("spawnScanner — timeout", () => {
  it("returns timedOut=true with partial stdout preserved when the timer fires first", async () => {
    (global as { __HOLD_OPEN__?: boolean }).__HOLD_OPEN__ = true;

    const resultP = spawnScanner("trufflehog", ["stdin"], {
      timeoutMs: 30,
      stdinInput: "fake body",
    });

    // Push some data after a short delay (before the timeout fires)
    // to simulate partial output.
    setTimeout(() => {
      const child = spawned[0]!;
      child.stdout.push('{"DetectorName":"Github","Raw":"ghp_partial"}\n');
    }, 5);

    const result = await resultP;

    // The timeout fired at 30 ms; the child hasn't closed yet. The
    // promise must resolve with timedOut=true and whatever partial
    // stdout we pushed.
    expect(result.timedOut).toBe(true);
    expect(result.stdout).toContain('{"DetectorName":"Github"');

    // Now the child eventually closes (the kill -9 is observed by
    // the OS as a close event). The `settled` guard must prevent
    // this from re-resolving the promise with timedOut=false.
    spawned[0]!.flushClose(null);
    // Give the event loop a tick so any erroneous re-resolve would
    // be observed.
    await new Promise((r) => setImmediate(r));
    expect(result.timedOut).toBe(true);
  }, 1000);
});

describe("spawnScanner — spawn error", () => {
  it("returns spawnError and spawnErrorCode when the child errors asynchronously", async () => {
    (global as { __SPAWN_ERROR__?: string }).__SPAWN_ERROR__ =
      "spawn trufflehog ENOENT";
    (global as { __SPAWN_ERROR_CODE__?: string }).__SPAWN_ERROR_CODE__ =
      "ENOENT";

    const result = await spawnScanner("trufflehog", ["stdin"], {
      timeoutMs: 1_000,
      stdinInput: "fake body",
    });

    expect(result.timedOut).toBe(false);
    expect(result.spawnError).toBe("spawn trufflehog ENOENT");
    expect(result.spawnErrorCode).toBe("ENOENT");
    expect(result.stdout).toBe("");
  });
});

describe("MAX_OUTPUT_BYTES", () => {
  it("is at least 1 MB so a 200 KB chat body fits in one chunk", () => {
    // Sanity: the cap should comfortably exceed any reasonable chat
    // body. If this drops below ~1 MB the scanner starts killing
    // real bodies on the first chunk read.
    expect(MAX_OUTPUT_BYTES).toBeGreaterThanOrEqual(1_000_000);
  });
});
