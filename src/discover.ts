import { OcGoModelInfo } from "./types";
import { OC_GO_MODELS } from "./types";

const GO_MODELS_API = "https://opencode.ai/zen/go/v1/models";
const ZEN_MODELS_API = "https://opencode.ai/zen/v1/models";
const DISCOVER_CACHE_TTL_MS = 3_600_000; // 1 hour

const FALLBACK_SPEC = {
  contextWindow: 131072,
  maxOutput: 65536,
  supportsVision: false,
  apiFormat: "openai" as const,
  thinkingMode: "none" as const,
};

let cachedDiscovered: OcGoModelInfo[] | null = null;
let cacheTime = 0;

const knownIds = new Set(OC_GO_MODELS.map((m) => m.id));

function parseModelId(id: string): string {
  return id
    .split("-")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

function inferBaseUrl(id: string): string | undefined {
  if (id.endsWith("-free")) return "https://opencode.ai/zen/v1";
  if (
    id.startsWith("claude-") ||
    id.startsWith("gemini-") ||
    id.startsWith("gpt-") ||
    id.startsWith("grok-build-") ||
    id === "big-pickle"
  ) {
    return "https://opencode.ai/zen/v1";
  }
  return undefined;
}

function inferApiFormat(id: string): "openai" | "anthropic" {
  if (id.startsWith("claude-")) return "anthropic";
  return "openai";
}

function inferVision(id: string): boolean {
  if (id.startsWith("claude-")) return true;
  if (id.startsWith("gemini-")) return true;
  if (id.startsWith("gpt-5.6-") || id.startsWith("gpt-5.5") || id.startsWith("gpt-5.4")) return !id.includes("nano") && !id.includes("mini");
  if (id.startsWith("gpt-5.3-") || id.startsWith("gpt-5.2-") || id.startsWith("gpt-5.1-") || id.startsWith("gpt-5-")) return false;
  if (id === "gpt-5.2" || id === "gpt-5.1" || id === "gpt-5") return true;
  if (id.startsWith("grok-build-")) return true;
  return false;
}

function inferThinking(id: string): "switchable" | "none" {
  if (id.startsWith("claude-")) return "switchable";
  if (id.startsWith("gemini-")) {
    if (id.includes("lite")) return "none";
    return "switchable";
  }
  if (id.includes("nano") || id.includes("mini") && !id.includes("codex-mini")) return "none";
  if (id.includes("codex")) {
    if (id.includes("mini") || id === "gpt-5-codex") return "none";
  }
  if (id.includes("-free")) return "none";
  return "switchable";
}

async function fetchModelIds(apiUrl: string): Promise<string[]> {
  try {
    const res = await fetch(apiUrl, { signal: AbortSignal.timeout(5000) });
    if (!res.ok) return [];
    const body = await res.json() as { data?: Array<{ id: string }> };
    return (body.data || []).map((m) => m.id);
  } catch {
    return [];
  }
}

function buildModelEntry(id: string): OcGoModelInfo {
  return {
    id,
    name: parseModelId(id),
    displayName: parseModelId(id),
    contextWindow: FALLBACK_SPEC.contextWindow,
    maxOutput: FALLBACK_SPEC.maxOutput,
    supportsTools: true,
    supportsVision: inferVision(id),
    apiFormat: inferApiFormat(id),
    thinkingMode: inferThinking(id),
    baseUrl: inferBaseUrl(id),
  };
}

export async function discoverModels(): Promise<OcGoModelInfo[]> {
  const now = Date.now();
  if (cachedDiscovered && now - cacheTime < DISCOVER_CACHE_TTL_MS) {
    return cachedDiscovered;
  }

  const [goIds, zenIds] = await Promise.all([
    fetchModelIds(GO_MODELS_API),
    fetchModelIds(ZEN_MODELS_API),
  ]);

  const apiIds = new Set([...goIds, ...zenIds]);
  const newEntries: OcGoModelInfo[] = [];

  for (const id of apiIds) {
    if (!knownIds.has(id)) {
      newEntries.push(buildModelEntry(id));
    }
  }

  cachedDiscovered = newEntries;
  cacheTime = now;

  if (newEntries.length > 0) {
    console.log(
      `[OpenCode Go Provider] Discovered ${newEntries.length} new model(s) from API:`,
      newEntries.map((m) => m.id).join(", ")
    );
  }

  return newEntries;
}

export function clearDiscoverCache(): void {
  cachedDiscovered = null;
  cacheTime = 0;
}

export function getAllModels(discovered: OcGoModelInfo[]): OcGoModelInfo[] {
  if (discovered.length === 0) return OC_GO_MODELS;
  const known = new Set(OC_GO_MODELS.map((m) => m.id));
  const merged = [...OC_GO_MODELS];
  for (const m of discovered) {
    if (!known.has(m.id)) {
      merged.push(m);
    }
  }
  return merged;
}
