import * as fs from "fs";
import * as path from "path";
import * as os from "os";

const DEBUG_LOG_PATH = path.join(os.homedir(), "oc-go-debug.log");
const MAX_LOG_SIZE = 5 * 1024 * 1024; // 5 MB
const TRIM_KEEP = 1 * 1024 * 1024; // Keep last 1 MB when rotating
const FLUSH_INTERVAL = 500; // ms

let buffer = "";
let flushTimer: ReturnType<typeof setInterval> | undefined;

function flushBuffer(): void {
  if (!buffer) return;
  const content = buffer;
  buffer = "";
  fs.promises
    .appendFile(DEBUG_LOG_PATH, content)
    .then(() => trimIfNeeded())
    .catch(() => {
      // Ignore write errors
    });
}

async function trimIfNeeded(): Promise<void> {
  try {
    const stat = await fs.promises.stat(DEBUG_LOG_PATH);
    if (stat.size < MAX_LOG_SIZE) return;
    const content = await fs.promises.readFile(DEBUG_LOG_PATH, "utf-8");
    const trimmed = content.slice(-TRIM_KEEP);
    await fs.promises.writeFile(DEBUG_LOG_PATH, trimmed);
  } catch {
    // Ignore trim errors
  }
}

function ensureTimer(): void {
  if (flushTimer !== undefined) return;
  flushTimer = setInterval(flushBuffer, FLUSH_INTERVAL);
  flushTimer.unref();
}

export function debugLog(msg: string, data?: Record<string, unknown>): void {
  const timestamp = new Date().toISOString();
  const line = data
    ? `[${timestamp}] ${msg} ${JSON.stringify(data)}\n`
    : `[${timestamp}] ${msg}\n`;
  buffer += line;
  ensureTimer();
}

export function flushLog(): void {
  if (flushTimer !== undefined) {
    clearInterval(flushTimer);
    flushTimer = undefined;
  }
  if (buffer) {
    try {
      fs.appendFileSync(DEBUG_LOG_PATH, buffer);
    } catch {
      // Ignore write errors
    }
    buffer = "";
  }
}
