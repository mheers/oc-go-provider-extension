/**
 * Integration test: drive the real `gitleaks` binary end-to-end
 * against a body of text that contains known secrets. Skipped when
 * gitleaks is not installed.
 *
 * This is the regression test for the bug where `runGitleaks` was
 * spawning gitleaks v8 with `--stdin` (which v8 doesn't accept) and
 * a stray positional `-` that made gitleaks scan the wrong directory.
 * The result was always "0 bytes scanned, no leaks found" regardless
 * of the input — every scan in production was silently passing.
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

(gitleaksAvailable() ? describe : describe.skip)(
  "scanAndRedact (integration with real gitleaks)",
  () => {
    beforeEach(() => {
      _resetAvailabilityCache();
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
