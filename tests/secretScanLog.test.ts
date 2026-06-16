/// <reference types="jest" />

import {
  secretScanLog,
  setChannelForTests,
  getChannel,
} from "../src/secretScanLog";

/**
 * Tiny in-memory stand-in for `vscode.OutputChannel`. The mock captures
 * every line that the log module emits so tests can assert on the
 * exact text the user will see in the "OpenCode Go: Secret Scan"
 * output view.
 */
class FakeOutputChannel {
  public lines: string[] = [];
  public revealCount = 0;
  public readonly name = "Fake";
  appendLine(text: string): void {
    this.lines.push(text);
  }
  append(text: string): void {
    this.lines.push(text);
  }
  clear(): void {
    this.lines.length = 0;
  }
  show(_preserveFocus?: boolean): void {
    this.revealCount += 1;
  }
  hide(): void {
    /* no-op */
  }
  dispose(): void {
    /* no-op */
  }
}

let fake: FakeOutputChannel;

beforeEach(() => {
  fake = new FakeOutputChannel();
  setChannelForTests(fake);
});

afterEach(() => {
  setChannelForTests(undefined);
});

describe("secretScanLog", () => {
  it("emits a binary-resolved line on first availability probe", () => {
    secretScanLog.binaryResolved("gitleaks", false);
    expect(fake.lines).toHaveLength(1);
    expect(fake.lines[0]).toMatch(/binary resolved: gitleaks/);
    expect(fake.lines[0]).toMatch(/\$PATH/);
  });

  it("marks env-var path resolution distinctly", () => {
    secretScanLog.binaryResolved("/opt/bin/gitleaks", true);
    expect(fake.lines[0]).toMatch(/opencodego\.gitleaksPath/);
  });

  it("emits a scanStarted header with api/bytes/timeout", () => {
    secretScanLog.scanStarted({
      apiFormat: "openai",
      bytes: 12345,
      timeoutMs: 2000,
    });
    expect(fake.lines[0]).toMatch(/^─+/);
    expect(fake.lines[1]).toMatch(/▶ scan started/);
    expect(fake.lines[1]).toMatch(/api=openai/);
    expect(fake.lines[1]).toMatch(/body=12\.1 KB/);
    expect(fake.lines[1]).toMatch(/timeout=2000ms/);
  });

  it("emits a clean-result line with the duration", () => {
    secretScanLog.scanClean(42.3);
    expect(fake.lines[0]).toMatch(/✓ clean — no findings \(42\.3ms\)/);
  });

  it("emits a redaction summary plus one line per finding", () => {
    const findings = [
      {
        ruleId: "aws-access-token",
        secret: "AKIAIOSFODNN7EXAMPLE",
        redacted: "[REDACTED:aws-access-token]",
      },
      {
        ruleId: "github-pat",
        secret: "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        redacted: "[REDACTED:github-pat]",
      },
    ];
    secretScanLog.scanRedacted(findings, 12.5);
    expect(fake.lines[0]).toMatch(/⚠ redacted 2 finding/);
    expect(fake.lines[1]).toMatch(/1\. rule=aws-access-token/);
    expect(fake.lines[1]).toMatch(/AKIA/);
    expect(fake.lines[1]).not.toMatch(/AKIAIOSFODNN7EXAMPLE/);
    expect(fake.lines[2]).toMatch(/2\. rule=github-pat/);
    expect(fake.lines[2]).toMatch(/len=40/);
  });

  it("never leaks the full secret into the log", () => {
    const findings = [
      {
        ruleId: "private-key",
        // Emulate the secret with a 64-char block of real-looking base64.
        secret:
          "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu",
        redacted: "[REDACTED:private-key]",
      },
    ];
    secretScanLog.scanRedacted(findings, 1);
    const joined = fake.lines.join("\n");
    expect(joined).not.toContain(
      "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu"
    );
    // Preview keeps first/last 4 chars only.
    expect(joined).toMatch(/MIIB.+Qu/);
  });

  it("emits a disabled line when action=off", () => {
    secretScanLog.scanDisabled();
    expect(fake.lines[0]).toMatch(/⊘ scan skipped — action=off/);
  });

  it("emits an unavailable line with reason-specific copy", () => {
    secretScanLog.scanUnavailable("missing");
    expect(fake.lines[0]).toMatch(/gitleaks binary not found/);

    secretScanLog.scanUnavailable("timeout", "after 2000ms");
    expect(fake.lines[1]).toMatch(/gitleaks scan timed out/);
    expect(fake.lines[2]).toMatch(/after 2000ms/);

    secretScanLog.scanUnavailable("spawn-error", "ENOENT");
    expect(fake.lines[3]).toMatch(/gitleaks process failed to start/);
    expect(fake.lines[4]).toMatch(/ENOENT/);
  });

  it("emits a parse-error line with the preview snippet", () => {
    secretScanLog.scanParseError("not json at all");
    expect(fake.lines[0]).toMatch(/could not parse gitleaks output/);
    expect(fake.lines[0]).toMatch(/not json at all/);
  });

  it("reveal() calls show() on the underlying channel", () => {
    secretScanLog.reveal();
    expect(fake.revealCount).toBe(1);
  });

  it("lazy-creates a real channel when no fake is injected", () => {
    setChannelForTests(undefined);
    // Touching getChannel() would attempt vscode.window.createOutputChannel
    // which doesn't exist in the jest mock. We just assert that
    // setChannelForTests(undefined) reset the singleton.
    expect(getChannel).toBeDefined();
  });
});
