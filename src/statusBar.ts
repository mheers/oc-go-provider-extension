import * as vscode from "vscode";
import type { SecretFinding } from "./secretScan";

export interface UsageMetrics {
  prompt_tokens: number;
  completion_tokens: number;
  cache_hit_tokens?: number;
  cache_miss_tokens?: number;
}

export interface SecretScanReport {
  apiFormat: "openai" | "anthropic";
  findings: SecretFinding[];
  redacted: boolean;
  at: number;
}

class OcGoStatusBar {
  private _item: vscode.StatusBarItem;
  private _cumulativeInput = 0;
  private _cumulativeOutput = 0;
  private _cumulativeCacheHit = 0;
  private _cumulativeCacheMiss = 0;
  private _maxInputTokens: number | undefined;
  private _promptTokens: number | undefined;
  private _lastScan: SecretScanReport | undefined;

  constructor(context: vscode.ExtensionContext) {
    this._item = vscode.window.createStatusBarItem(
      vscode.StatusBarAlignment.Right,
      100
    );
    this._item.command = "opencode-go.manage";
    this._item.text = "$(hubot) OC Go";
    this._item.tooltip = "OpenCode Go Provider";
    this._item.show();
    context.subscriptions.push(this._item);
  }

  setActiveModel(maxInputTokens: number): void {
    this._maxInputTokens = maxInputTokens;
    this._updateText();
  }

  setPromptTokens(tokens: number): void {
    this._promptTokens = tokens;
    this._updateText();
  }

  recordUsage(usage: UsageMetrics): void {
    this._cumulativeInput += usage.prompt_tokens ?? 0;
    this._cumulativeOutput += usage.completion_tokens ?? 0;
    this._cumulativeCacheHit += usage.cache_hit_tokens ?? 0;
    this._cumulativeCacheMiss += usage.cache_miss_tokens ?? 0;
    this._updateText();
    this._updateTooltip();
  }

  maybeResetForNewConversation(hasAssistantTurn: boolean): void {
    if (!hasAssistantTurn) {
      this._cumulativeInput = 0;
      this._cumulativeOutput = 0;
      this._cumulativeCacheHit = 0;
      this._cumulativeCacheMiss = 0;
      this._updateText();
    }
  }

  recordSecretScan(report: Omit<SecretScanReport, "at">): void {
    this._lastScan = { ...report, at: Date.now() };
    this._updateText();
    this._updateTooltip();
  }

  getLastScan(): SecretScanReport | undefined {
    return this._lastScan;
  }

  private _updateText(): void {
    const parts: string[] = ["$(hubot) OC Go"];
    if (
      this._promptTokens !== undefined &&
      this._maxInputTokens !== undefined
    ) {
      parts.push(
        `${this._fmt(this._promptTokens)}/${this._fmt(this._maxInputTokens)}`
      );
    }
    if (this._cumulativeInput > 0 || this._cumulativeOutput > 0) {
      parts.push(
        `${this._fmt(this._cumulativeInput)}in/${this._fmt(this._cumulativeOutput)}out`
      );
    }
    this._item.text = parts.join(" ");
  }

  private _updateTooltip(): void {
    const lines: string[] = ["OpenCode Go Token Usage"];
    lines.push(`Input: ${this._fmt(this._cumulativeInput)}`);
    lines.push(`Output: ${this._fmt(this._cumulativeOutput)}`);
    if (this._cumulativeCacheHit > 0 || this._cumulativeCacheMiss > 0) {
      const total = this._cumulativeCacheHit + this._cumulativeCacheMiss;
      const rate =
        total > 0 ? Math.round((this._cumulativeCacheHit / total) * 100) : 0;
      lines.push(`Cache hit rate: ${rate}%`);
    }
    this._item.tooltip = lines.join("\n");
  }

  private _fmt(n: number): string {
    if (n >= 1_000_000_000) return `${(n / 1_000_000_000).toFixed(1)}B`;
    if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
    if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
    return String(n);
  }

  dispose(): void {
    this._item.dispose();
  }
}

let _statusBar: OcGoStatusBar | undefined;

export function initStatusBar(context: vscode.ExtensionContext): void {
  _statusBar = new OcGoStatusBar(context);
}

export function statusBarRecordUsage(usage: UsageMetrics): void {
  _statusBar?.recordUsage(usage);
}

export function statusBarSetActiveModel(maxInputTokens: number): void {
  _statusBar?.setActiveModel(maxInputTokens);
}

export function statusBarSetPromptTokens(tokens: number): void {
  _statusBar?.setPromptTokens(tokens);
}

export function statusBarMaybeReset(hasAssistantTurn: boolean): void {
  _statusBar?.maybeResetForNewConversation(hasAssistantTurn);
}

export function statusBarRecordSecretScan(
  report: Omit<SecretScanReport, "at">
): void {
  _statusBar?.recordSecretScan(report);
}

export function statusBarGetLastScan(): SecretScanReport | undefined {
  return _statusBar?.getLastScan();
}
