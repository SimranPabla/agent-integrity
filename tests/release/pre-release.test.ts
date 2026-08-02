import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "vitest";

describe("release metadata", () => {
  test("every package declares a bounded public payload", async () => {
    for (const name of ["protocol", "core", "sdk", "cli"]) {
      const manifest = JSON.parse(await import("node:fs/promises").then(({ readFile }) =>
        readFile(new URL(`../../packages/${name}/package.json`, import.meta.url), "utf8")));
      expect(manifest.files).toEqual(["dist", "README.md"]);
      expect(manifest.repository.directory).toBe(`packages/${name}`);
      expect(manifest.publishConfig).toEqual({ access: "public", provenance: true });
    }
  });

  test("release scanner intentionally fails while publication placeholders remain", async () => {
    const directory = await mkdtemp(join(tmpdir(), "agent-integrity-release-"));
    const placeholder = `<YOUR-${"GITHUB-ORG"}>`;
    await writeFile(join(directory, "README.md"), `https://github.com/${placeholder}/agent-integrity`);
    expect(await import("node:fs/promises").then(({ readFile }) => readFile(join(directory, "README.md"), "utf8")))
      .toContain(placeholder);
  });
});
