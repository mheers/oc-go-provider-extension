/**
 * Integration test: drive the real `gitleaks` and `trufflehog`
 * binaries end-to-end against a body of text that contains known
 * secrets. Skipped per-backend when that binary is not installed.
 *
 * This is also the regression test for the bug where `runGitleaks`
 * was spawning gitleaks v8 with `--stdin` (which v8 doesn't accept)
 * and a stray positional `-` that made gitleaks scan the wrong
 * directory. The result was always "0 bytes scanned, no leaks found"
 * regardless of the input — every scan in production was silently
 * passing. The fix uses gitleaks' `stdin` subcommand, which reads
 * arbitrary content from the stdin pipe and emits a JSON report on
 * stdout (`--report-path -`), with no temp file on disk.
 */
import { existsSync, readFileSync } from "fs";
import { join } from "path";

import { scanAndRedact, _resetAvailabilityCache } from "../src/secretScan";

const DEMO_DOTENV = join(
  __dirname,
  "..",
  "..",
  "worst-secret-leaks-demo",
  ".env"
);

function gitleaksAvailable(): boolean {
  if (existsSync("/home/marcel/go/bin/gitleaks")) return true;
  if (process.env.OPENCODEGO_GITLEAKS_PATH) return true;
  return (process.env.PATH ?? "")
    .split(":")
    .some((p) => existsSync(join(p, "gitleaks")));
}

function trufflehogAvailable(): boolean {
  if (existsSync("/home/marcel/go/bin/trufflehog")) return true;
  if (process.env.OPENCODEGO_TRUFFLEHOG_PATH) return true;
  return (process.env.PATH ?? "")
    .split(":")
    .some((p) => existsSync(join(p, "trufflehog")));
}

(gitleaksAvailable() ? describe : describe.skip)(
  "scanAndRedact (integration with real gitleaks)",
  () => {
    beforeEach(() => {
      _resetAvailabilityCache();
      process.env["OPENCODEGO_SCANNER"] = "gitleaks";
    });

    it("returns a non-empty redacted body when given the demo .env", async () => {
      if (!existsSync(DEMO_DOTENV)) {
        // The companion demo project may not be on disk; skip silently
        // so this test passes on machines without it.
        return;
      }
      const body = readFileSync(DEMO_DOTENV, "utf8");
      const result = await scanAndRedact(body, { timeoutMs: 5_000 });

      // We don't pin the exact finding count: gitleaks' default rules
      // have varied over versions, and the demo .env is hand-tuned.
      // What matters for this regression test is that gitleaks
      // actually scans stdin and reports findings when the input
      // contains secrets that match the default rules. Before the
      // fix this would always be `findings.length === 0`.
      expect(result.findings.length).toBeGreaterThanOrEqual(1);
      // Every reported finding must round-trip back into the input as
      // a [REDACTED:<rule>] placeholder.
      for (const f of result.findings) {
        expect(result.text).toContain(`[REDACTED:${f.ruleId}]`);
        // And the original secret must no longer appear in the body.
        expect(result.text).not.toContain(f.secret);
      }
    });

    it("finds the canonical slack-bot-token in a small synthetic payload", async () => {
      // Hard-coded well-formed Slack token that is unambiguously a
      // leak to every gitleaks version since v8.18. Using a synthetic
      // payload (rather than the demo .env) keeps the test independent
      // of the demo project's .gitleaks.toml content.
      const slackToken = "xoxb-1111111111-2222222222-abcdefghijklmnopqrstuvwx";
      const body = `const t = "${slackToken}";\n`;
      const result = await scanAndRedact(body, { timeoutMs: 5_000 });

      expect(result.findings.length).toBeGreaterThanOrEqual(1);
      expect(result.findings.some((f) => f.ruleId === "slack-bot-token")).toBe(
        true
      );
      expect(result.text).toContain("[REDACTED:slack-bot-token]");
      expect(result.text).not.toContain(slackToken);
    });
  }
);

(trufflehogAvailable() ? describe : describe.skip)(
  "scanAndRedact (integration with real trufflehog)",
  () => {
    beforeEach(() => {
      _resetAvailabilityCache();
      process.env["OPENCODEGO_SCANNER"] = "trufflehog";
    });

    it("finds the canonical github PAT in a small synthetic payload", async () => {
      // Hard-coded well-formed GitHub Personal Access Token. TruffleHog's
      // default detectors flag this without verification.
      const githubPat = "ghp_M7p9Lq3RtV34X7K2H8Q5N1B6J0Z9D4Y7S2P8";
      const body = `const t = "${githubPat}";\n`;
      const result = await scanAndRedact(body, { timeoutMs: 5_000 });

      expect(result.findings.length).toBeGreaterThanOrEqual(1);
      // TruffleHog's detector name is the human-friendly form,
      // e.g. "Github" rather than "github-pat".
      expect(result.findings.some((f) => f.ruleId === "Github")).toBe(true);
      expect(result.text).toContain("[REDACTED:Github]");
      expect(result.text).not.toContain(githubPat);
    });

    it("returns a non-empty redacted body when given the demo .env", async () => {
      if (!existsSync(DEMO_DOTENV)) {
        return;
      }
      const body = readFileSync(DEMO_DOTENV, "utf8");
      const result = await scanAndRedact(body, { timeoutMs: 10_000 });

      // Note: we do NOT assert a minimum number of findings here.
      // The demo .env is hand-tuned for gitleaks' default rules; its
      // synthetic secrets often don't match trufflehog's detector
      // regexes (which are tuned for real-world entropy/shape). The
      // real assertion for trufflehog is that the binary runs, the
      // input is staged, the JSON output is parsed, and the response
      // shape matches `ScanResult`. The synthetic github-PAT test
      // above covers the "findings > 0" path deterministically.
      expect(result).toHaveProperty("findings");
      expect(result).toHaveProperty("redacted");
      expect(result).toHaveProperty("text");
      // If trufflehog did find anything, the redaction contract must
      // hold: every reported finding must round-trip back into the
      // input as a [REDACTED:<rule>] placeholder and the secret
      // must no longer appear in the body.
      for (const f of result.findings) {
        expect(result.text).toContain(`[REDACTED:${f.ruleId}]`);
        expect(result.text).not.toContain(f.secret);
      }
    }, 15_000);
  }
);
