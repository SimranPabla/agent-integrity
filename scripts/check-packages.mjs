import { execFileSync } from "node:child_process";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const packages = ["protocol", "core", "sdk", "cli"];
const workspace = new URL("../", import.meta.url).pathname;
const staging = join(tmpdir(), `agent-integrity-pack-${process.pid}`);
await mkdir(staging, { recursive: true });

try {
  for (const name of packages) {
    const output = execFileSync("npm", ["pack", "--dry-run", "--json", `./packages/${name}`], {
      cwd: workspace,
      encoding: "utf8",
    });
    const [manifest] = JSON.parse(output);
    const paths = manifest.files.map((file) => file.path);
    for (const required of ["package.json", "README.md"]) {
      if (!paths.includes(required)) throw new Error(`${name}: pack is missing ${required}`);
    }
    if (!paths.some((path) => path.startsWith("dist/"))) throw new Error(`${name}: pack is missing dist output`);
    if (paths.some((path) => path.includes("tests/") || path.includes("src/"))) {
      throw new Error(`${name}: pack contains source or test files outside the declared public payload`);
    }
    await writeFile(join(staging, `${name}.json`), JSON.stringify(manifest, null, 2));
    console.log(`${manifest.name}: ${paths.length} files, ${manifest.size} bytes`);
  }
} finally {
  await rm(staging, { recursive: true, force: true });
}
