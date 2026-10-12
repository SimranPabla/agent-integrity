import { access, readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";

const root = new URL("../..", import.meta.url).pathname;

describe("workspace package exports", () => {
  it("sidecar emits JavaScript but cannot enter the exact public pack set", async () => {
    const manifest = JSON.parse(await readFile(join(root, "packages/sidecar/package.json"), "utf8"));
    expect(manifest.private).toBe(true);
    await expect(access(join(root, "packages/sidecar/dist/cli.js"))).resolves.toBeUndefined();
    const script = await readFile(join(root, "scripts/check-packages.mjs"), "utf8");
    expect(script).toContain('const packages = ["protocol", "core", "sdk", "cli"]');
    expect(script).toContain('private sidecar compiled fail-closed executable passed');
    for (const name of ["protocol", "core", "sdk", "cli"]) {
      const publicManifest = JSON.parse(await readFile(join(root, "packages", name, "package.json"), "utf8"));
      expect(publicManifest.private).not.toBe(true);
      expect(Object.keys(publicManifest.dependencies ?? {})).not.toContain("@agent-integrity/sidecar");
    }
  });
  for (const name of ["protocol", "core", "sdk"] as const) {
    it(`${name} exports an emitted JavaScript and declaration file`, async () => {
      const directory = join(root, "packages", name);
      const manifest = JSON.parse(await readFile(join(directory, "package.json"), "utf8")) as {
        exports: string;
        types: string;
      };
      await expect(access(join(directory, manifest.exports))).resolves.toBeUndefined();
      await expect(access(join(directory, manifest.types))).resolves.toBeUndefined();
      expect(dirname(manifest.exports)).toBe(dirname(manifest.types));
    });
  }
});
