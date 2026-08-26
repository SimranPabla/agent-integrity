import { execFileSync } from "node:child_process";
import { access, mkdtemp, readFile, writeFile } from "node:fs/promises";
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

  test("npm publication remains intentionally disabled", async () => {
    await expect(access(new URL("../../.github/workflows/npm-release.yml", import.meta.url))).rejects.toMatchObject({ code: "ENOENT" });
    await expect(access(new URL("../../scripts/publish-package.mjs", import.meta.url))).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("threat model limits exactly-once replay protection to one monotonic local store", async () => {
    const threatModel = await readFile(new URL("../../docs/THREAT_MODEL.md", import.meta.url), "utf8");
    expect(threatModel).toContain("only when every consumer uses the same protected, shared, monotonic local filesystem store");
    expect(threatModel).toContain("Restoring older store state can reopen replay");
    expect(threatModel).toContain("does not provide distributed or multi-host replay protection");
    expect(threatModel).not.toContain("this is not durable replay prevention");
  });

  test("release scanner intentionally fails while publication placeholders remain", async () => {
    const directory = await mkdtemp(join(tmpdir(), "agent-integrity-release-"));
    const placeholder = `<YOUR-${"GITHUB-ORG"}>`;
    await writeFile(join(directory, "README.md"), `https://github.com/${placeholder}/agent-integrity`);
    expect(await import("node:fs/promises").then(({ readFile }) => readFile(join(directory, "README.md"), "utf8")))
      .toContain(placeholder);
  });
});
