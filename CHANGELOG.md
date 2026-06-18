# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **Critical: trufflehog was silently dropping every unverified finding.** The scanner invoked `trufflehog filesystem` with `--no-verification` but without `--results=unverified,unknown`. When `--no-verification` is set, trufflehog drops the `verified` bucket **and** the `unverified` bucket, so every unverified detection (i.e. almost every secret we'd ever see in the chat path, since we never phone home) was silently absent from the NDJSON output. The result was a clean `findings: []` report, the original body was forwarded to the LLM, and the user-visible log said "✓ clean". This caused the `ghp_…` token in `worst-secret-leaks-demo/cmd/server/main.go` (and any other real-world secret that doesn't happen to also be `verified`) to leak through. The fix adds `--results=unverified,unknown` so unverified detections are emitted and the redaction logic runs against them. The test suite now pins the exact argv to prevent regression.

- **TruffleHog now uses the `stdin` subcommand instead of `filesystem`.** Both subcommands accept the same flags, performance is equivalent, but `stdin` removes the per-scan temp-file staging (one less write + one less unlink per outbound request) and closes a small attack surface where a crash mid-scan could leave the request body — including any not-yet-redacted secrets — on disk in `/tmp`.

### Changed

- The "scan unavailable" and "could not parse … output" log lines in the "OpenCode Go: Secret Scan" output channel are now backend-agnostic: they interpolate the name of the currently configured scanner (read from `OPENCODEGO_SCANNER`, defaulting to `trufflehog`) instead of hard-coding "gitleaks". Previously these messages lied when the user had selected `trufflehog`.

- The trufflehog backend now also emits a `SECRET-SCAN` debug log line on clean runs (with `findingCount: 0` and the elapsed `durationMs`) so the duration is visible in the extension log even when nothing was redacted.

### Added

- **Pluggable secret scanner** with [trufflehog](https://github.com/trufflesecurity/trufflehog) as the new default. TruffleHog's detector corpus (~800 detectors, entropy-aware) is substantially larger and more actively maintained than gitleaks'. Verification is off by default (`--no-verification`) so the chat path never makes network calls. New setting `opencodego.secretScanner` (`"trufflehog"` | `"gitleaks"`, default `"trufflehog"`) selects the backend; `opencodego.trufflehogPath` overrides the binary path. The previous `opencodego.gitleaksPath` setting is preserved. Internal refactor: secret scanning is now a `src/scanners/` module with a `Scanner` interface and a registry; adding a new backend is one new file in that directory.

- **LLM-friendly hint when secrets are redacted.** When the outbound scanner replaces a secret with `[REDACTED:<rule>]`, the model previously saw a bare placeholder and often tried to "decode" it or asked the user for the original value. The extension now appends a single short system message (OpenAI format) or prepends to the top-level `system` field (Anthropic format) telling the LLM that the placeholders are intentional redactions and should be ignored. The hint is idempotent across multi-turn conversations and only injected on the first redacted turn; clean runs are not annotated. Helper: `injectRedactionHintForOpenAI` / `injectRedactionHintForAnthropic` in `src/utils.ts`.

### Changed

- Status bar is now a real quick-pick menu. Clicking it (or running "OpenCode Go: Manage OpenCode Go Provider") opens a menu with: set/update/clear the API key, select the vision proxy model, view secret scan status and log, and jump to OpenCode Go settings. The previous "enter the API key" input box is now reached via the "Set/Update API Key…" menu item.

- `redactRequestBody` in `src/provider.ts` now returns `{ body, redacted }` (a `RedactedRequestBody` object) instead of a bare `Json`, so callers can decide whether to inject the redaction hint without re-parsing the response.

## [0.7.0] - 2026-05-19

### Added

- Enhanced image analysis tool with vision model support and logging

### Changed

- Improved code formatting and readability in package.json, provider.ts, and utils.ts

## [0.6.1] - 2026-05-08

### Fixed

- Cap image token estimation to avoid base64 size overcounting
- Truncate OCR image analysis text to prevent oversized prompts

## [0.6.0] - 2026-05-04

### Added

- **MiMo-V2.5-Pro** model (`mimo-v2.5-pro`) — 1T params (42B activated), 1M context, 131K max output, tool calling support
- **MiMo-V2.5** model (`mimo-v2.5`) — 311B params, 262K context, 65K max output, multimodal vision, audio, video & tool calling support (native omnimodal)

## [0.5.0] - 2026-04-25

### Added

- **DeepSeek V4 Flash** model (`deepseek-v4-flash`) — 284B params (13B activated), 1M context, 384K max output, tool calling support
- **DeepSeek V4 Pro** model (`deepseek-v4-pro`) — 1.6T params (49B activated), 1M context, 384K max output, tool calling support

## [0.4.1] - 2026-04-22

### Fixed

- Fixed Kimi (Moonshot AI) 400 error "thinking is enabled but reasoning_content is missing in assistant tool call message" by including `reasoning_content` field in all assistant messages

## [0.4.0] - 2026-04-21

### Added

- **Kimi K2.6** model (`kimi-k2.6`) — 262K context, 262K max output, multimodal vision & tool calling support

## [0.3.0] - 2026-04-16

### Added

- **Qwen3.5 Plus** model (`qwen3.5-plus`) — 1M context, 65K max output, vision & tool calling support
- **Qwen3.6 Plus** model (`qwen3.6-plus`) — 1M context, 65K max output, vision & tool calling support

## [0.2.1] - 2026-04-14

### Fixed

- Fixed Kimi K2.5 API error "invalid temperature: only 1 is allowed for this model" by adding `fixedTemperature` support to model configuration

## [0.2.0] - 2026-04-14

### Changed

- Aligned model token limits with OpenRouter published specifications
  - **Kimi K2.5**: context 131K → 262K, max output 8K → 65K
  - **MiMo-V2-Pro**: context 131K → 1M, max output 16K → 131K
  - **MiMo-V2-Omni**: context 131K → 262K, max output 16K → 65K
  - **MiniMax M2.5**: context 1M → 196K, max output 16K → 131K
  - **MiniMax M2.7**: context 1M → 196K, max output 16K → 131K
  - GLM-5 and GLM-5.1 remain unchanged (already aligned)

### Fixed

- Updated README and package.json descriptions for accuracy
- Added token limit disclaimer to README

## [0.1.0] - 2026-04-14

- The First Release.
