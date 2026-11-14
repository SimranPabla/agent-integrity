import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";
// Focused source-only verification avoids rebuilding shared outputs while another owner is active.
export default defineConfig({ resolve: { alias: { "@agent-integrity/core": fileURLToPath(new URL("../../../core/src/index.ts", import.meta.url)) } } });
