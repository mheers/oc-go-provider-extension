/// <reference types="jest" />

import { EventEmitter } from "events";
import { Readable, Writable } from "stream";

import {
  scanAndRedact,
  availability,
  _resetAvailabilityCache,
  getConfigPath,
} from "../src/secretScan";
import { debugLog } from "../src/logging";

/**
 * Build a fake `ChildProcess` whose stdin/stdout/stderr are streams
 * we can drive from the test. We then monkey-patch `child_process.spawn`
 * to return it, so `scanAndRedact` runs against a fake "gitleaks".
 *
 * The mock keeps a registry of pending responses per call, keyed by
 * the first CLI argument, so we can distinguish the `--version` probe
 * (sent by `availability()`) from the actual `detect --pipe -s` scan.
 *
 * The `reportPath` for the fake scan is parsed out of the spawn args
 * and the queued `stdout` is written to that file on close() so the
 * real code path (which reads the JSON report from disk) is exercised.
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
        child.responded = true;
        if (next.stdout) child.stdout.push(next.stdout);
        (child.stdout as Readable).push(null);
        if (next.stderr) child.stderr.push(next.stderr);
        (child.stderr as Readable).push(null);
        // The fake "gitleaks" writes its JSON report to whatever path
        // was passed via `--report-path` (parsed out of args here).
        // Production reads the report back from disk on `close`.
        const reportPath = extractReportPath(args);
        if (reportPath && next.stdout !== undefined) {
          try {
            require("fs").writeFileSync(reportPath, next.stdout, "utf8");
          } catch {
            /* swallow — production code will report the read error */
          }
        }
        child.emit("close", next.exitCode ?? 0);
      };
      child.stdin.on("finish", send);
      child.stdin.on("close", send);
      return child;
    }),
  };
});

function extractReportPath(args: string[]): string | undefined {
  const i = args.indexOf("--report-path");
  if (i < 0 || i + 1 >= args.length) return undefined;
  return args[i + 1];
}

jest.mock("../src/logging", () => ({
  debugLog: jest.fn(),
}));

const mockedDebugLog = debugLog as unknown as jest.Mock;

beforeEach(() => {
  queue = [];
  spawned = [];
  _resetAvailabilityCache();
  jest.clearAllMocks();
  // Force the facade to dispatch to the gitleaks backend, regardless
  // of what the default is.
  process.env["OPENCODEGO_SCANNER"] = "gitleaks";
  delete process.env["OPENCODEGO_GITLEAKS_PATH"];
  delete process.env["OPENCODEGO_TRUFFLEHOG_PATH"];
});

function enqueueVersionProbe(): void {
  queue.push({
    matchArgs: (args) => args[0] === "--version",
    stdout: "gitleaks version 8.24.0\n",
    exitCode: 0,
  });
}

function enqueueScan(stdout: string, exitCode = 0): void {
  queue.push({
    matchArgs: (args) => args[0] === "detect",
    stdout,
    exitCode,
  });
}

const AVAILABLE = "available" as const;

describe("scanAndRedact", () => {
  it("returns the input unchanged when gitleaks finds nothing", async () => {
    enqueueScan("[]");
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

  it("redacts a single secret reported as a JSON array", async () => {
    const finding = JSON.stringify([
      {
        RuleID: "aws-access-token",
        Secret: "AKIAIOSFODNN7EXAMPLE",
        Match: "AKIAIOSFODNN7EXAMPLE",
        File: "-",
        Line: 1,
      },
    ]);
    enqueueScan(finding);
    const result = await scanAndRedact('token = "AKIAIOSFODNN7EXAMPLE"', {
      timeoutMs: 1000,
      availabilityOverride: AVAILABLE,
    });
    expect(result.redacted).toBe(true);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].ruleId).toBe("aws-access-token");
    expect(result.findings[0].secret).toBe("AKIAIOSFODNN7EXAMPLE");
    expect(result.text).toBe('token = "[REDACTED:aws-access-token]"');
  });

  it("redacts a single secret reported as a bare JSON object", async () => {
    const finding = JSON.stringify({
      RuleID: "generic-api-key",
      Secret: "supersecretvalue123",
      Match: "supersecretvalue123",
    });
    enqueueScan(finding);
    const result = await scanAndRedact('apiKey: "supersecretvalue123"', {
      timeoutMs: 1000,
      availabilityOverride: AVAILABLE,
    });
    expect(result.redacted).toBe(true);
    expect(result.findings[0].redacted).toBe("[REDACTED:generic-api-key]");
    expect(result.text).toBe('apiKey: "[REDACTED:generic-api-key]"');
  });

  it("handles multiple findings and applies all redactions", async () => {
    const findings = JSON.stringify([
      {
        RuleID: "aws-access-token",
        Secret: "AKIAIOSFODNN7EXAMPLE",
        Match: "AKIAIOSFODNN7EXAMPLE",
      },
      {
        RuleID: "github-pat",
        Secret: "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        Match: "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
      },
    ]);
    enqueueScan(findings);
    const result = await scanAndRedact(
      'aws="AKIAIOSFODNN7EXAMPLE" gh="ghp_abcdefghijklmnopqrstuvwxyz0123456789"',
      { timeoutMs: 1000, availabilityOverride: AVAILABLE }
    );
    expect(result.redacted).toBe(true);
    expect(result.findings).toHaveLength(2);
    expect(result.text).toBe(
      'aws="[REDACTED:aws-access-token]" gh="[REDACTED:github-pat]"'
    );
  });

  it("tolerates trailing garbage after the JSON", async () => {
    const findings = JSON.stringify([
      { RuleID: "slack-token", Secret: "xoxb-1234", Match: "xoxb-1234" },
    ]);
    enqueueScan(`${findings}\nnoise\n`);
    const result = await scanAndRedact("token=xoxb-1234", {
      timeoutMs: 1000,
      availabilityOverride: AVAILABLE,
    });
    expect(result.redacted).toBe(true);
    expect(result.findings[0].ruleId).toBe("slack-token");
  });

  it("returns the input unchanged when gitleaks output is unparseable", async () => {
    enqueueScan("not json at all");
    const result = await scanAndRedact("hello", {
      timeoutMs: 1000,
      availabilityOverride: AVAILABLE,
    });
    expect(result.redacted).toBe(false);
    expect(result.text).toBe("hello");
  });

  it("returns the input unchanged when gitleaks binary is missing", async () => {
    const result = await scanAndRedact('AKIA"hello"', {
      timeoutMs: 1000,
      availabilityOverride: "missing",
    });
    expect(result.redacted).toBe(false);
    expect(result.findings).toEqual([]);
    // No scan should have been spawned
    expect(spawned.find((c) => c.args[0] === "detect")).toBeUndefined();
  });

  it("logs findings via debugLog", async () => {
    const findings = JSON.stringify([
      { RuleID: "stripe-secret", Secret: "sk_live_xx", Match: "sk_live_xx" },
    ]);
    enqueueScan(findings);
    await scanAndRedact('s = "sk_live_xx"', {
      timeoutMs: 1000,
      availabilityOverride: AVAILABLE,
    });
    expect(mockedDebugLog).toHaveBeenCalledWith(
      "SECRET-SCAN",
      expect.objectContaining({
        findingCount: 1,
        rules: ["stripe-secret"],
      })
    );
  });
});

describe("availability", () => {
  it("returns 'disabled' when action is 'off'", async () => {
    const result = await availability("off");
    expect(result).toBe("disabled");
  });

  it("returns 'missing' when action is 'redact' and no probe response is queued", async () => {
    const result = await availability("redact");
    expect(result).toBe("missing");
  });

  it("caches the result", async () => {
    enqueueVersionProbe();
    const a = await availability("redact");
    const b = await availability("redact");
    expect(a).toBe(b);
  });
});

describe("getConfigPath", () => {
  it("returns the env-var override when set", () => {
    process.env["OPENCODEGO_GITLEAKS_PATH"] = "/opt/bin/gitleaks";
    expect(getConfigPath()).toBe("/opt/bin/gitleaks");
    delete process.env["OPENCODEGO_GITLEAKS_PATH"];
  });

  it("falls back to 'gitleaks' on PATH when no override", () => {
    delete process.env["OPENCODEGO_GITLEAKS_PATH"];
    expect(getConfigPath()).toBe("gitleaks");
  });
});
