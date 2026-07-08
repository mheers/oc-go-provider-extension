/// <reference types="jest" />

import * as vscode from "vscode";
import * as path from "path";

import {
  OcGoChatModelProvider,
  getSecretScanConfig,
} from "../src/provider";
import { secrets } from "../__mocks__/vscode";
import { secretScanLog } from "../src/secretScanLog";

function createDoneStream(): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new TextEncoder().encode("data: [DONE]\n"));
      controller.close();
    },
  });
}

function createToken(): vscode.CancellationToken {
  return {
    isCancellationRequested: false,
    onCancellationRequested: jest.fn(() => ({ dispose: jest.fn() })),
  } as unknown as vscode.CancellationToken;
}

describe("OcGoChatModelProvider", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (secrets.get as jest.Mock).mockResolvedValue("test-api-key");
    (vscode.workspace.getConfiguration as jest.Mock).mockReturnValue({
      get: jest.fn((_key: string, defaultValue: unknown) => defaultValue),
    });
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      body: createDoneStream(),
    });
  });

  it("should expose the full context window as maxInputTokens", async () => {
    const provider = new OcGoChatModelProvider(
      secrets as unknown as vscode.SecretStorage,
      "jest-agent"
    );

    const models = await provider.provideLanguageModelChatInformation(
      { silent: true } as vscode.PrepareLanguageModelChatModelOptions,
      createToken()
    );

    const glm5 = models.find((m) => m.id === "glm-5");
    expect(glm5).toBeDefined();
    expect(glm5?.maxInputTokens).toBe(202752 - Math.min(131072, 65536));
    expect(glm5?.maxOutputTokens).toBe(131072);
  });

  it("should allow prompts larger than the old reserved-output cap", async () => {
    const provider = new OcGoChatModelProvider(
      secrets as unknown as vscode.SecretStorage,
      "jest-agent"
    );
    const models = await provider.provideLanguageModelChatInformation(
      { silent: true } as vscode.PrepareLanguageModelChatModelOptions,
      createToken()
    );
    const glm5 = models.find((m) => m.id === "glm-5");
    if (!glm5) {
      throw new Error("glm-5 not found");
    }

    const largePrompt = "a".repeat(72000 * 4);
    const messages = [vscode.LanguageModelChatMessage.User(largePrompt)];
    const progress = {
      report: jest.fn(),
    } as unknown as vscode.Progress<vscode.LanguageModelResponsePart>;

    await expect(
      provider.provideLanguageModelChatResponse(
        glm5,
        messages,
        {},
        progress,
        createToken()
      )
    ).resolves.toBeUndefined();

    expect(global.fetch).toHaveBeenCalledTimes(1);
  });

  it("should use the official default max_tokens when not specified", async () => {
    const provider = new OcGoChatModelProvider(
      secrets as unknown as vscode.SecretStorage,
      "jest-agent"
    );
    const models = await provider.provideLanguageModelChatInformation(
      { silent: true } as vscode.PrepareLanguageModelChatModelOptions,
      createToken()
    );
    const kimiK25 = models.find((m) => m.id === "kimi-k2.5");
    if (!kimiK25) {
      throw new Error("kimi-k2.5 not found");
    }

    const messages = [vscode.LanguageModelChatMessage.User("hello")];
    const progress = {
      report: jest.fn(),
    } as unknown as vscode.Progress<vscode.LanguageModelResponsePart>;

    await provider.provideLanguageModelChatResponse(
      kimiK25,
      messages,
      {},
      progress,
      createToken()
    );

    expect(global.fetch).toHaveBeenCalledTimes(1);
    const requestInit = (global.fetch as jest.Mock).mock.calls[0]?.[1] as {
      body?: string;
    };
    expect(requestInit.body).toBeDefined();
    const requestBody = JSON.parse(requestInit.body ?? "{}");
    expect(requestBody.max_tokens).toBe(65536);
  });

  it("should reject prompts that exceed the documented context window", async () => {
    const provider = new OcGoChatModelProvider(
      secrets as unknown as vscode.SecretStorage,
      "jest-agent"
    );
    const models = await provider.provideLanguageModelChatInformation(
      { silent: true } as vscode.PrepareLanguageModelChatModelOptions,
      createToken()
    );
    const kimiK25 = models.find((m) => m.id === "kimi-k2.5");
    if (!kimiK25) {
      throw new Error("kimi-k2.5 not found");
    }

    const tooLargePrompt = "a".repeat(131073 * 4);
    const messages = [vscode.LanguageModelChatMessage.User(tooLargePrompt)];
    const progress = {
      report: jest.fn(),
    } as unknown as vscode.Progress<vscode.LanguageModelResponsePart>;

    await expect(
      provider.provideLanguageModelChatResponse(
        kimiK25,
        messages,
        {},
        progress,
        createToken()
      )
    ).rejects.toThrow("Message exceeds token limit.");

    expect(global.fetch).not.toHaveBeenCalled();
  });

  it("should count tokens for text data parts in provideTokenCount", async () => {
    const provider = new OcGoChatModelProvider(
      secrets as unknown as vscode.SecretStorage,
      "jest-agent"
    );
    const models = await provider.provideLanguageModelChatInformation(
      { silent: true } as vscode.PrepareLanguageModelChatModelOptions,
      createToken()
    );
    const glm5 = models.find((m) => m.id === "glm-5");
    if (!glm5) {
      throw new Error("glm-5 not found");
    }

    const text = "text from LanguageModelDataPart";
    const message = vscode.LanguageModelChatMessage.User([
      vscode.LanguageModelDataPart.text(text),
    ]);

    const count = await provider.provideTokenCount(
      glm5,
      message,
      createToken()
    );
    expect(count).toBe(Math.ceil(text.length / 2));
  });
});

describe("getSecretScanConfig", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    delete process.env["OPENCODEGO_SCANNER"];
    delete process.env["OPENCODEGO_GITLEAKS_PATH"];
    delete process.env["OPENCODEGO_TRUFFLEHOG_PATH"];
  });

  it("uses the bundled trufflehog config when no override is set", () => {
    (vscode.workspace.getConfiguration as jest.Mock).mockReturnValue({
      get: jest.fn((key: string, defaultValue: unknown) => {
        if (key === "secretScanner") return "trufflehog";
        if (key === "secretScan") return "redact";
        if (key === "trufflehogConfigPath") return "";
        return defaultValue;
      }),
    });

    const config = getSecretScanConfig();

    expect(config.scanner).toBe("trufflehog");
    expect(config.trufflehogConfigPath).toBe(
      path.resolve(process.cwd(), "config", "trufflehog.yml")
    );
    expect(config.trufflehogConfigLabel).toBe(
      `bundled default (${path.resolve(process.cwd(), "config", "trufflehog.yml")})`
    );
  });

  it("uses an absolute trufflehog config override as-is", () => {
    const customPath = path.resolve(process.cwd(), "config", "trufflehog.yml");
    (vscode.workspace.getConfiguration as jest.Mock).mockReturnValue({
      get: jest.fn((key: string, defaultValue: unknown) => {
        if (key === "secretScanner") return "trufflehog";
        if (key === "secretScan") return "redact";
        if (key === "trufflehogConfigPath") return customPath;
        return defaultValue;
      }),
    });

    const config = getSecretScanConfig();

    expect(config.trufflehogConfigPath).toBe(customPath);
    expect(config.trufflehogConfigLabel).toBe(customPath);
  });

  it("falls back to the bundled config for a relative trufflehog override", () => {
    const fallbackSpy = jest.spyOn(secretScanLog, "configFallback");
    (vscode.workspace.getConfiguration as jest.Mock).mockReturnValue({
      get: jest.fn((key: string, defaultValue: unknown) => {
        if (key === "secretScanner") return "trufflehog";
        if (key === "secretScan") return "redact";
        if (key === "trufflehogConfigPath") return "./relative.yml";
        return defaultValue;
      }),
    });

    const config = getSecretScanConfig();

    expect(config.trufflehogConfigPath).toBe(
      path.resolve(process.cwd(), "config", "trufflehog.yml")
    );
    expect(fallbackSpy).toHaveBeenCalledWith(
      "./relative.yml",
      path.resolve(process.cwd(), "config", "trufflehog.yml")
    );
  });
});
