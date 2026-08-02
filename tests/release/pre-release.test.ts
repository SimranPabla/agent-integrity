import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "vitest";

describe("release metadata", () => {
  test("every package declares a bounded public payload", async () => {
    for (const name of ["protocol", "core", "sdk", "cli"]) {
      const manifest = JSON.parse(await import("node:fs/promises").then(({ readFile }) =>
        readFile(new URL(`../../packages/${name}/package.json`, import.meta.url), "utf8")));
      expect(manifest.files).toEqual(name === "cli" ? ["dist", "README.md", "!dist/.tsbuildinfo"] : ["dist", "README.md"]);
      expect(manifest.repository.directory).toBe(`packages/${name}`);
      expect(manifest.publishConfig).toEqual({ access: "public", provenance: true });
    }
  });

  test("the monorepo root cannot be published", async () => {
    const manifest = JSON.parse(await readFile(new URL("../../package.json", import.meta.url), "utf8"));
    expect(manifest.private).toBe(true);
  });

  test("package gate performs a clean tarball install without leaving archives in the repository", () => {
    const root = new URL("../../", import.meta.url);
    const archivesBefore = execFileSync(process.execPath, ["--input-type=module", "--eval", `import {readdir} from 'node:fs/promises'; console.log(JSON.stringify((await readdir('.')).filter((name) => name.endsWith('.tgz'))))`], { cwd: root, encoding: "utf8" });
    const output = execFileSync(process.execPath, [new URL("../../scripts/check-packages.mjs", import.meta.url).pathname], { cwd: root, encoding: "utf8" });
    const archivesAfter = execFileSync(process.execPath, ["--input-type=module", "--eval", `import {readdir} from 'node:fs/promises'; console.log(JSON.stringify((await readdir('.')).filter((name) => name.endsWith('.tgz'))))`], { cwd: root, encoding: "utf8" });
    expect(output).toContain("clean tarball install, imports, and CLI executable passed");
    expect(archivesAfter).toBe(archivesBefore);
  }, 60_000);

  test("npm publication workflow is tag-only, least-privilege, ordered, and placeholder-gated", async () => {
    const workflow = await readFile(new URL("../../.github/workflows/npm-release.yml", import.meta.url), "utf8");
    expect(workflow).toContain('tags:\n      - "v*"');
    expect(workflow).not.toMatch(/pull_request:|branches:/u);
    expect(workflow).toContain("contents: read");
    expect(workflow).toContain("id-token: write");
    expect(workflow).toContain("npm run verify");
    expect(workflow).toContain("npm run release:check");
    expect(workflow).toContain("npm run pack:check");
    const publishes = ["protocol", "core", "sdk", "cli"].map((name) => workflow.indexOf(`npm publish ./packages/${name} --access public --provenance --tag alpha`));
    expect(publishes.every((position) => position >= 0)).toBe(true);
    expect(publishes).toEqual([...publishes].sort((left, right) => left - right));
    expect(workflow.indexOf("npm run release:check")).toBeLessThan(publishes[0]!);
  });

  test("release scanner intentionally fails while publication placeholders remain", async () => {
    const directory = await mkdtemp(join(tmpdir(), "agent-integrity-release-"));
    const placeholder = `<YOUR-${"GITHUB-ORG"}>`;
    await writeFile(join(directory, "README.md"), `https://github.com/${placeholder}/agent-integrity`);
    expect(await import("node:fs/promises").then(({ readFile }) => readFile(join(directory, "README.md"), "utf8")))
      .toContain(placeholder);
  });
});
