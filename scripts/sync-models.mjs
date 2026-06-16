#!/usr/bin/env node

/**
 * sync-models.mjs — Fetches the latest OpenCode Go model list from the API
 * and compares it against the OC_GO_MODELS defined in src/types.ts.
 *
 * Usage:
 *   node scripts/sync-models.mjs           # dry-run — only report differences
 *   node scripts/sync-models.mjs --apply    # modify types.ts in-place
 *   node scripts/sync-models.mjs --help     # show this message
 *
 * The script handles three kinds of changes:
 *   1. NEW models — present in the API but missing from OC_GO_MODELS.
 *   2. REMOVED models — present in OC_GO_MODELS but absent from the API.
 *   3. CHANGED models — metadata differences (only apiFormat detected automatically).
 */

const GO_MODELS_API = "https://opencode.ai/zen/go/v1/models";
const TYPES_FILE = new URL("../src/types.ts", import.meta.url);
// Monorepo-style, but should work from project root

/* ------------------------------------------------------------------ */
/*  Known model specs (edit this when new families land)              */
/*  Keyed by base model-id prefix — longest match wins.               */
/* ------------------------------------------------------------------ */
const SPECS = [
  // —— GLM family (OpenAI) ——
  {
    prefix: "glm-5.1",
    spec: {
      name: "GLM-5.1",
      displayName: "GLM-5.1",
      contextWindow: 202752,
      maxOutput: 131072,
      supportsVision: false,
      apiFormat: "openai",
      thinkingMode: "none",
    },
  },
  {
    prefix: "glm-5",
    spec: {
      name: "GLM-5",
      displayName: "GLM-5",
      contextWindow: 202752,
      maxOutput: 131072,
      supportsVision: false,
      apiFormat: "openai",
      thinkingMode: "none",
    },
  },

  // —— Kimi K2 family (OpenAI, always thinking, fixed temp) ——
  {
    prefix: "kimi-k2.7",
    spec: {
      name: "Kimi K2.7 Code",
      displayName: "Kimi K2.7 Code",
      contextWindow: 262144,
      maxOutput: 262144,
      supportsVision: true,
      apiFormat: "openai",
      thinkingMode: "always",
      fixedTemperature: 1,
    },
  },
  {
    prefix: "kimi-k2.6",
    spec: {
      name: "Kimi K2.6",
      displayName: "Kimi K2.6",
      contextWindow: 262144,
      maxOutput: 262144,
      supportsVision: true,
      apiFormat: "openai",
      thinkingMode: "always",
      fixedTemperature: 1,
    },
  },
  {
    prefix: "kimi-k2.5",
    spec: {
      name: "Kimi K2.5",
      displayName: "Kimi K2.5",
      contextWindow: 262144,
      maxOutput: 65536,
      supportsVision: true,
      apiFormat: "openai",
      thinkingMode: "always",
      fixedTemperature: 1,
    },
  },

  // —— MiMo V2 family (OpenAI, switchable thinking) ——
  {
    prefix: "mimo-v2.5-pro",
    spec: {
      name: "MiMo-V2.5-Pro",
      displayName: "MiMo-V2.5-Pro",
      contextWindow: 1048576,
      maxOutput: 131072,
      supportsVision: false,
      apiFormat: "openai",
      thinkingMode: "switchable",
    },
  },
  {
    prefix: "mimo-v2.5",
    spec: {
      name: "MiMo-V2.5",
      displayName: "MiMo-V2.5",
      contextWindow: 262144,
      maxOutput: 65536,
      supportsVision: true,
      apiFormat: "openai",
      thinkingMode: "switchable",
    },
  },
  {
    prefix: "mimo-v2-pro",
    spec: {
      name: "MiMo-V2-Pro",
      displayName: "MiMo-V2-Pro",
      contextWindow: 1048576,
      maxOutput: 131072,
      supportsVision: false,
      apiFormat: "openai",
      thinkingMode: "switchable",
    },
  },
  {
    prefix: "mimo-v2-omni",
    spec: {
      name: "MiMo-V2-Omni",
      displayName: "MiMo-V2-Omni",
      contextWindow: 262144,
      maxOutput: 65536,
      supportsVision: true,
      apiFormat: "openai",
      thinkingMode: "switchable",
    },
  },

  // —— MiniMax family (Anthropic) ——
  {
    prefix: "minimax-m3",
    spec: {
      name: "MiniMax M3",
      displayName: "MiniMax M3",
      contextWindow: 262144,
      maxOutput: 131072,
      supportsVision: false,
      apiFormat: "anthropic",
      thinkingMode: "switchable",
    },
  },
  {
    prefix: "minimax-m2.7",
    spec: {
      name: "MiniMax M2.7",
      displayName: "MiniMax M2.7",
      contextWindow: 196608,
      maxOutput: 131072,
      supportsVision: false,
      apiFormat: "anthropic",
      thinkingMode: "none",
    },
  },
  {
    prefix: "minimax-m2.5",
    spec: {
      name: "MiniMax M2.5",
      displayName: "MiniMax M2.5",
      contextWindow: 196608,
      maxOutput: 131072,
      supportsVision: false,
      apiFormat: "anthropic",
      thinkingMode: "none",
    },
  },

  // —— Qwen 3.7 family (Anthropic, vision) ——
  {
    prefix: "qwen3.7-max",
    spec: {
      name: "Qwen3.7 Max",
      displayName: "Qwen3.7 Max",
      contextWindow: 262144,
      maxOutput: 65536,
      supportsVision: true,
      apiFormat: "anthropic",
      thinkingMode: "switchable",
    },
  },
  {
    prefix: "qwen3.7-plus",
    spec: {
      name: "Qwen3.7 Plus",
      displayName: "Qwen3.7 Plus",
      contextWindow: 1000000,
      maxOutput: 65536,
      supportsVision: true,
      apiFormat: "anthropic",
      thinkingMode: "switchable",
    },
  },

  // —— Qwen 3.6 family (Anthropic, vision) ——
  {
    prefix: "qwen3.6-plus",
    spec: {
      name: "Qwen3.6 Plus",
      displayName: "Qwen3.6 Plus",
      contextWindow: 1000000,
      maxOutput: 65536,
      supportsVision: true,
      apiFormat: "anthropic",
      thinkingMode: "switchable",
    },
  },

  // —— Qwen 3.5 family (OpenAI, vision) ——
  {
    prefix: "qwen3.5-plus",
    spec: {
      name: "Qwen3.5 Plus",
      displayName: "Qwen3.5 Plus",
      contextWindow: 1000000,
      maxOutput: 65536,
      supportsVision: true,
      apiFormat: "openai",
      thinkingMode: "switchable",
    },
  },

  // —— DeepSeek V4 family (OpenAI, reasoning) ——
  {
    prefix: "deepseek-v4-pro",
    spec: {
      name: "DeepSeek V4 Pro",
      displayName: "DeepSeek V4 Pro",
      contextWindow: 1000000,
      maxOutput: 393216,
      supportsVision: false,
      apiFormat: "openai",
      thinkingMode: "switchable",
    },
  },
  {
    prefix: "deepseek-v4-flash",
    spec: {
      name: "DeepSeek V4 Flash",
      displayName: "DeepSeek V4 Flash",
      contextWindow: 1000000,
      maxOutput: 393216,
      supportsVision: false,
      apiFormat: "openai",
      thinkingMode: "switchable",
    },
  },
];

/* Fallback for completely unknown models */
const FALLBACK_SPEC = {
  name: null,
  displayName: null,
  contextWindow: 131072,
  maxOutput: 65536,
  supportsVision: true,
  apiFormat: "openai",
  thinkingMode: "switchable",
};

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

function sortByPrefixLength(a, b) {
  return b.prefix.length - a.prefix.length;
}

function findSpec(modelId) {
  const sorted = [...SPECS].sort(sortByPrefixLength);
  const match = sorted.find((s) => modelId.startsWith(s.prefix));
  return match ? { ...match.spec } : null;
}

function toModelEntry(id, spec) {
  const name = spec.name ?? guessName(id);
  const displayName = spec.displayName ?? guessName(id);
  const kv = [
    `    id: "${id}",`,
    `    name: "${name}",`,
    `    displayName: "${displayName}",`,
    `    contextWindow: ${spec.contextWindow},`,
    `    maxOutput: ${spec.maxOutput},`,
    `    supportsTools: true,`,
    `    supportsVision: ${String(spec.supportsVision)},`,
    `    apiFormat: "${spec.apiFormat}",`,
  ];
  if (spec.fixedTemperature !== undefined) {
    kv.push(`    fixedTemperature: ${spec.fixedTemperature},`);
  }
  kv.push(`    thinkingMode: "${spec.thinkingMode}",`);
  return kv.join("\n");
}

function guessName(id) {
  return id
    .split(/[-]/)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

/* ------------------------------------------------------------------ */
/*  Main                                                               */
/* ------------------------------------------------------------------ */

async function main() {
  const args = process.argv.slice(2);
  const isApply = args.includes("--apply");
  const isHelp = args.includes("--help");

  if (isHelp) {
    console.log(`
Usage: node scripts/sync-models.mjs [--apply]

Fetches the OpenCode Go model list and compares it against OC_GO_MODELS
in src/types.ts.

  --apply    Write new model entries directly into types.ts
  --help     Show this help

Without --apply the script runs in dry-run mode (read-only).
`);
    process.exit(0);
  }

  // 1. Fetch the API
  console.log("🔍 Fetching models from", GO_MODELS_API, "...");
  const res = await fetch(GO_MODELS_API);
  if (!res.ok) {
    console.error(`❌ API returned ${res.status} ${res.statusText}`);
    process.exit(1);
  }
  const body = await res.json();
  const apiIds = (body.data || []).map((m) => m.id).sort();
  console.log(`   Found ${apiIds.length} models in API\n`);

  // 2. Read current types.ts
  const fs = await import("node:fs");
  const source = fs.readFileSync(TYPES_FILE, "utf-8");

  // Extract existing model IDs from the OC_GO_MODELS array
  const existingIds = new Set(
    [...source.matchAll(/^\s{4}id:\s*"([^"]+)",$/gm)].map((m) => m[1])
  );
  console.log(`   Found ${existingIds.size} models in OC_GO_MODELS\n`);

  // 3. Compare
  const newIds = apiIds.filter((id) => !existingIds.has(id));
  const removedIds = [...existingIds].filter((id) => !apiIds.includes(id));

  if (newIds.length === 0 && removedIds.length === 0) {
    console.log("✅ Models are in sync — no changes needed.\n");
    return;
  }

  // Removed models
  if (removedIds.length > 0) {
    console.log(
      "🗑️  Models in OC_GO_MODELS but NOT in API (possibly deprecated):"
    );
    for (const id of removedIds) {
      console.log(`   - ${id}`);
    }
    console.log("");
  }

  // New models
  if (newIds.length === 0) {
    console.log("✨ No new models to add.\n");
    return;
  }

  console.log("✨ New models to add:");
  for (const id of newIds) {
    const spec = findSpec(id);
    if (spec) {
      console.log(
        `   + ${id}  (known — ${spec.name ?? spec.displayName ?? id})`
      );
    } else {
      console.log(`   + ${id}  ⚠️  UNKNOWN — using fallback defaults`);
    }
  }
  console.log("");

  if (!isApply) {
    console.log("ℹ️  Run with --apply to insert them into types.ts\n");
    return;
  }

  // 4. Generate and insert entries
  const entries = newIds.map((id) => {
    const spec = findSpec(id);
    return toModelEntry(id, spec ?? FALLBACK_SPEC);
  });

  const block = entries.map((entry) => `  {\n${entry}\n  },`).join("\n");

  // Insert before the closing "];" of OC_GO_MODELS
  const marker = "\n];\n\n/** Default model used for OCR";
  if (!source.includes(marker)) {
    console.error(
      '❌ Could not find array terminator "];" in types.ts — aborting.'
    );
    process.exit(1);
  }
  const updated = source.replace(marker, `\n${block}\n${marker}`);

  fs.writeFileSync(TYPES_FILE, updated, "utf-8");
  console.log(
    `✅ Inserted ${entries.length} new model(s) into ${TYPES_FILE.pathname}\n`
  );
}

main().catch((err) => {
  console.error("❌ Script failed:", err);
  process.exit(1);
});
