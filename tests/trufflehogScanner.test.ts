/// <reference types="jest" />

import { EventEmitter } from "events";
import { Readable, Writable } from "stream";

import {
  scanAndRedact,
  availability,
  _resetAvailabilityCache,
  getConfigPath,
  getConfigName,
} from "../src/secretScan";
import { debugLog } from "../src/logging";

/**
 * Drive the `trufflehog` backend through the same `child_process.spawn`
 * mock pattern used by `secretScan.test.ts`.
 *
 * Key facts exercised here:
 *   - TruffleHog is invoked as `trufflehog stdin …` — the request body
 *     is piped to the child process's stdin, not staged to a temp
 *     file. The queue's `matchArgs` looks for the `stdin` subcommand.
 *   - TruffleHog emits one finding per line (NDJSON) on stdout, with
 *     progress log lines possibly interleaved. We stage
 *     `--log-level=-1` to suppress those in production; in tests we
 *     can also queue log-prefixed lines to verify the parser ignores
 *     them.
 *   - The flag set MUST include `--results=unverified,unknown`. Without
 *     it, `--no-verification` causes trufflehog to silently drop every
 *     unverified finding from the JSON output, so secrets would leak
 *     through. This test pins the exact argv to catch regressions.
 */
class FakeChildProcess extends EventEmitter {
  public stdin: Writable;
  public stdout: Readable;
  public stderr: Readable;
  public killed = false;
  public args: string[];
  public responded = false;
  constructor(args: string[]) {
    super();
    this.args = args;
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
    if (!this.responded) {
      this.responded = true;
      (this.stdout as Readable).push(null);
      (this.stderr as Readable).push(null);
      this.emit("close", null);
    }
    return true;
  }
}

interface QueuedResponse {
  matchArgs?: (args: string[]) => boolean;
  stdout?: string;
  stderr?: string;
  exitCode?: number;
  /**
   * When true, the fake child will not auto-close on its `stdin`
   * `finish` event — it stays open until the test calls
   * `spawned[i].flushClose()`. Used by the timeout regression
   * test so the runner's kill-by-timer can fire.
   */
  holdOpen?: boolean;
}

let queue: QueuedResponse[] = [];
let spawned: FakeChildProcess[] = [];

function popResponse(args: string[]): QueuedResponse {
  for (let i = 0; i < queue.length; i++) {
    const item = queue[i]!;
    if (!item.matchArgs || item.matchArgs(args)) {
      queue.splice(i, 1);
      return item;
    }
  }
  return {};
}

jest.mock("child_process", () => {
  const real = jest.requireActual("child_process");
  return {
    ...real,
    spawn: jest.fn((_binary: string, args: string[]) => {
      const child = new FakeChildProcess(args);
      spawned.push(child);
      const next = popResponse(args);
      const send = (): void => {
        if (child.responded) return;
        if (next.holdOpen) {
          // Test wants the child to stay open past the runner's
          // timer. Push whatever data the test staged and stop —
          // do not emit `close` and do not push the EOF sentinel.
          if (next.stdout) child.stdout.push(next.stdout);
          if (next.stderr) child.stderr.push(next.stderr);
          return;
        }
        child.responded = true;
        if (next.stdout) child.stdout.push(next.stdout);
        (child.stdout as Readable).push(null);
        if (next.stderr) child.stderr.push(next.stderr);
        (child.stderr as Readable).push(null);
        child.emit("close", next.exitCode ?? 0);
      };
      child.stdin.on("finish", send);
      child.stdin.on("close", send);
      return child;
    }),
  };
});

jest.mock("../src/logging", () => ({
  debugLog: jest.fn(),
}));

const mockedDebugLog = debugLog as unknown as jest.Mock;

beforeEach(() => {
  queue = [];
  spawned = [];
  _resetAvailabilityCache();
  jest.clearAllMocks();
  // Force the facade to dispatch to the trufflehog backend.
  process.env["OPENCODEGO_SCANNER"] = "trufflehog";
  delete process.env["OPENCODEGO_GITLEAKS_PATH"];
  delete process.env["OPENCODEGO_TRUFFLEHOG_PATH"];
});

function enqueueVersionProbe(): void {
  queue.push({
    matchArgs: (args) => args[0] === "--version",
    stdout: "trufflehog 3.95.5\n",
    exitCode: 0,
  });
}

function enqueueStdinScan(stdout: string, exitCode = 0): void {
  queue.push({
    matchArgs: (args) => args[0] === "stdin",
    stdout,
    exitCode,
  });
}

function enqueueHeldStdinScan(partialStdout: string): void {
  queue.push({
    matchArgs: (args) => args[0] === "stdin",
    stdout: partialStdout,
    holdOpen: true,
  });
}

const AVAILABLE = "available" as const;

describe("scanAndRedact (trufflehog backend)", () => {
  it("returns the input unchanged when trufflehog finds nothing", async () => {
    enqueueStdinScan("");
    const result = await scanAndRedact("hello world", {
      timeoutMs: 1000,
      availabilityOverride: AVAILABLE,
    });
    expect(result.redacted).toBe(false);
    expect(result.findings).toEqual([]);
    expect(result.text).toBe("hello world");
  });

  it("returns the input unchanged for empty input", async () => {
    const result = await scanAndRedact("", {
      timeoutMs: 1000,
      availabilityOverride: AVAILABLE,
    });
    expect(result.redacted).toBe(false);
    expect(result.text).toBe("");
  });

  it("redacts a single finding from an NDJSON line", async () => {
    const finding = JSON.stringify({
      DetectorName: "Github",
      DetectorType: 8,
      Raw: "ghp_M7p9Lq3RtV34X7K2H8Q5N1B6J0Z9D4Y7S2P8",
      Redacted: "",
      SourceMetadata: {
        Data: {
          Filesystem: { file: "/tmp/payload.txt", line: 3 },
        },
      },
    });
    enqueueStdinScan(`${finding}\n`);
    const result = await scanAndRedact(
      'const gh = "ghp_M7p9Lq3RtV34X7K2H8Q5N1B6J0Z9D4Y7S2P8";',
      { timeoutMs: 1000, availabilityOverride: AVAILABLE }
    );
    expect(result.redacted).toBe(true);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].ruleId).toBe("Github");
    expect(result.findings[0].secret).toBe(
      "ghp_M7p9Lq3RtV34X7K2H8Q5N1B6J0Z9D4Y7S2P8"
    );
    expect(result.findings[0].redacted).toBe("[REDACTED:Github]");
    expect(result.text).toBe('const gh = "[REDACTED:Github]";');
  });

  it("redacts multiple findings spread across NDJSON lines", async () => {
    const a = JSON.stringify({
      DetectorName: "Github",
      Raw: "ghp_M7p9Lq3RtV34X7K2H8Q5N1B6J0Z9D4Y7S2P8",
    });
    const b = JSON.stringify({
      DetectorName: "AWS",
      Raw: "AKIAIOSFODNN7EXAMPLE",
    });
    enqueueStdinScan(`${a}\n${b}\n`);
    const result = await scanAndRedact(
      'aws="AKIAIOSFODNN7EXAMPLE"; gh="ghp_M7p9Lq3RtV34X7K2H8Q5N1B6J0Z9D4Y7S2P8";',
      { timeoutMs: 1000, availabilityOverride: AVAILABLE }
    );
    expect(result.redacted).toBe(true);
    expect(result.findings).toHaveLength(2);
    expect(result.text).toBe('aws="[REDACTED:AWS]"; gh="[REDACTED:Github]";');
  });

  it("returns timedOut=true and the original body when the scan exceeds its timeout", async () => {
    // Regression test: a 2 s scan on a 80 KB body used to silently
    // return `{ redacted: false, findings: [], text: <body> }` after
    // the runner's kill-by-timer fired, which the façade then
    // reported as "clean — no findings" — the worst possible
    // outcome, because the body was sent to the LLM unredacted. The
    // contract now is: when the kill fires, the scanner returns
    // `timedOut: true` with the original text and the façade emits
    // a distinct log line so the user can tell the cases apart.
    enqueueHeldStdinScan("");
    const body =
      'aws="AKIAIOSFODNN7EXAMPLE"; gh="ghp_M7p9Lq3RtV34X7K2H8Q5N1B6J0Z9D4Y7S2P8";';
    const result = await scanAndRedact(body, {
      timeoutMs: 30,
      availabilityOverride: AVAILABLE,
    });
    // The result MUST signal the timeout so the façade can emit a
    // distinct log line, and MUST NOT mark the body as redacted.
    expect(result.timedOut).toBe(true);
    expect(result.redacted).toBe(false);
    expect(result.findings).toEqual([]);
    // The original body is returned unchanged — applying a
    // partial redaction would be worse than no redaction at all
    // (the unread tail of the body could still contain secrets).
    expect(result.text).toBe(body);
    // The debug log MUST mention the timeout so the post-mortem
    // trail in ~/oc-go-debug.log distinguishes this from a clean
    // run.
    expect(mockedDebugLog).toHaveBeenCalledWith(
      "SECRET-SCAN-TIMEOUT",
      expect.objectContaining({
        backend: "trufflehog",
        timeoutMs: 30,
      })
    );
  });

  it("ignores non-finding lines (log lines, banner) in the NDJSON output", async () => {
    const finding = JSON.stringify({
      DetectorName: "Github",
      Raw: "ghp_M7p9Lq3RtV34X7K2H8Q5N1B6J0Z9D4Y7S2P8",
    });
    const noise = [
      "",
      "not json",
      '{"level":"info-0","msg":"running source"}',
      "---",
    ].join("\n");
    enqueueStdinScan(`${noise}\n${finding}\n`);
    const result = await scanAndRedact(
      'const gh = "ghp_M7p9Lq3RtV34X7K2H8Q5N1B6J0Z9D4Y7S2P8";',
      { timeoutMs: 1000, availabilityOverride: AVAILABLE }
    );
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].ruleId).toBe("Github");
  });

  it("skips finding lines missing DetectorName or Raw", async () => {
    const good = JSON.stringify({
      DetectorName: "Github",
      Raw: "ghp_M7p9Lq3RtV34X7K2H8Q5N1B6J0Z9D4Y7S2P8",
    });
    const noDetector = JSON.stringify({ Raw: "no-detector" });
    const noRaw = JSON.stringify({ DetectorName: "NoRaw" });
    enqueueStdinScan(`${good}\n${noDetector}\n${noRaw}\n`);
    const result = await scanAndRedact(
      'const gh = "ghp_M7p9Lq3RtV34X7K2H8Q5N1B6J0Z9D4Y7S2P8";',
      { timeoutMs: 1000, availabilityOverride: AVAILABLE }
    );
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].ruleId).toBe("Github");
  });

  it("returns the input unchanged when trufflehog binary is missing", async () => {
    const result = await scanAndRedact('any "input"', {
      timeoutMs: 1000,
      availabilityOverride: "missing",
    });
    expect(result.redacted).toBe(false);
    expect(result.findings).toEqual([]);
    expect(spawned.find((c) => c.args[0] === "stdin")).toBeUndefined();
  });

  it("logs findings via debugLog with backend=trufflehog", async () => {
    const finding = JSON.stringify({
      DetectorName: "Github",
      Raw: "ghp_M7p9Lq3RtV34X7K2H8Q5N1B6J0Z9D4Y7S2P8",
    });
    enqueueStdinScan(`${finding}\n`);
    await scanAndRedact('s = "ghp_M7p9Lq3RtV34X7K2H8Q5N1B6J0Z9D4Y7S2P8"', {
      timeoutMs: 1000,
      availabilityOverride: AVAILABLE,
    });
    expect(mockedDebugLog).toHaveBeenCalledWith(
      "SECRET-SCAN",
      expect.objectContaining({
        backend: "trufflehog",
        findingCount: 1,
        rules: ["Github"],
      })
    );
  });

  it("invokes trufflehog via the `stdin` subcommand (no temp file)", async () => {
    enqueueStdinScan("");
    await scanAndRedact("hello world", {
      timeoutMs: 1000,
      availabilityOverride: AVAILABLE,
    });
    const call = spawned.find((c) => c.args[0] === "stdin");
    expect(call).toBeDefined();
    // The full arg list is pinned: `filesystem` is no longer used
    // (stdin keeps the body out of /tmp), and `--results=unverified,unknown`
    // is the load-bearing flag that makes the scanner actually
    // report unverified findings.
    expect(call?.args).toEqual([
      "stdin",
      "--no-verification",
      "--no-update",
      "--no-color",
      "--json",
      "--log-level=-1",
      "--filter-entropy=3.0",
      "--results=unverified,unknown",
    ]);
  });

  it("passes the resolved trufflehog config via --config", async () => {
    enqueueStdinScan("");
    await scanAndRedact("hello world", {
      timeoutMs: 1000,
      availabilityOverride: AVAILABLE,
      configPath: "/tmp/trufflehog-custom.yml",
    });
    const call = spawned.find((c) => c.args[0] === "stdin");
    expect(call?.args).toContain("--config=/tmp/trufflehog-custom.yml");
  });

  it("passes the request body to trufflehog via stdin (no positional path)", async () => {
    enqueueStdinScan("");
    await scanAndRedact("hello world", {
      timeoutMs: 1000,
      availabilityOverride: AVAILABLE,
    });
    const call = spawned.find((c) => c.args[0] === "stdin");
    // No positional <path> arg should follow the flag set.
    expect(call?.args).not.toContain("payload");
    expect(call?.args).not.toContain("--directory");
  });

  it("also emits a SECRET-SCAN log line on a clean run (duration only)", async () => {
    enqueueStdinScan("");
    await scanAndRedact("hello world", {
      timeoutMs: 1000,
      availabilityOverride: AVAILABLE,
    });
    expect(mockedDebugLog).toHaveBeenCalledWith(
      "SECRET-SCAN",
      expect.objectContaining({
        backend: "trufflehog",
        findingCount: 0,
      })
    );
  });
});

describe("availability (trufflehog backend)", () => {
  it("returns 'disabled' when action is 'off'", async () => {
    const result = await availability("off");
    expect(result).toBe("disabled");
  });

  it("returns 'missing' when no probe response is queued", async () => {
    const result = await availability("redact");
    expect(result).toBe("missing");
  });

  it("caches the result after a successful probe", async () => {
    enqueueVersionProbe();
    const a = await availability("redact");
    const b = await availability("redact");
    expect(a).toBe(b);
    expect(a).toBe("available");
  });
});

describe("trufflehog config helpers", () => {
  it("getConfigPath honours the trufflehog env-var override", () => {
    process.env["OPENCODEGO_TRUFFLEHOG_PATH"] = "/opt/bin/trufflehog";
    expect(getConfigPath()).toBe("/opt/bin/trufflehog");
    delete process.env["OPENCODEGO_TRUFFLEHOG_PATH"];
  });

  it("getConfigPath falls back to 'trufflehog' on PATH", () => {
    delete process.env["OPENCODEGO_TRUFFLEHOG_PATH"];
    expect(getConfigPath()).toBe("trufflehog");
  });

  it("getConfigName reports 'trufflehog' when OPENCODEGO_SCANNER=trufflehog", () => {
    process.env["OPENCODEGO_SCANNER"] = "trufflehog";
    expect(getConfigName()).toBe("trufflehog");
  });
});
