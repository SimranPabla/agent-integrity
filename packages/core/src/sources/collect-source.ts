import { createHash } from "node:crypto";
import { open } from "node:fs/promises";
import { resolveAllowedSourcePath } from "./path-boundary.js";

export interface CollectedSource {
  readonly path: string;
  readonly sha256: string;
  readonly size: number;
}

export async function collectSource(options: {
  readonly projectRoot: string;
  readonly allowedRoots: readonly string[];
  readonly sourcePath: string;
}): Promise<CollectedSource> {
  const resolved = await resolveAllowedSourcePath(options);
  const handle = await open(resolved.realPath, "r");
  try {
    const stats = await handle.stat();
    if (!stats.isFile()) throw new Error("source path must resolve to a regular file");
    const bytes = await handle.readFile();
    return {
      path: resolved.relativePath,
      sha256: createHash("sha256").update(bytes).digest("hex"),
      size: bytes.byteLength
    };
  } finally {
    await handle.close();
  }
}
