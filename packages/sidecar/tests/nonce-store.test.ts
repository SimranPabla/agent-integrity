import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, link, lstat, mkdir, mkdtemp, readFile, readdir, rename, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { FileNonceStore, type NonceRecord } from "../src/index.js";

const DIGEST = "a".repeat(64);
const CHILD_DIRECTORY = process.env.AGENT_INTEGRITY_NONCE_CHILD_DIRECTORY;
const HOSTILE_UMASK_DIRECTORY = process.env.AGENT_INTEGRITY_NONCE_HOSTILE_UMASK_DIRECTORY;
function record(nonce = "nonce-1", keyId = "key-1"): NonceRecord {
  return { version: 1, clientId: "cage", keyId, nonce, timestampMs: 1_800_000_000_000, bodyDigest: DIGEST, retainedUntilMs: 1_800_000_060_001 };
}
function nonceKey(value: NonceRecord): string {
  const fields = [value.clientId, value.nonce];
  const parts: Buffer[] = [];
  for (const field of fields) {
    const bytes = Buffer.from(field, "utf8");
    const length = Buffer.alloc(4);
    length.writeUInt32BE(bytes.length);
    parts.push(length, bytes);
  }
  return createHash("sha256").update(Buffer.concat(parts)).digest("hex");
}
function recordPath(directory: string, value: NonceRecord): string { return join(directory, "records", `${nonceKey(value)}.json`); }
async function root(): Promise<string> { return mkdtemp(join(tmpdir(), "sidecar-nonce-")); }

describe("nonce child-process helper", () => {
  it.skipIf(CHILD_DIRECTORY === undefined)("consumes the requested nonce", async () => {
    await new FileNonceStore(CHILD_DIRECTORY!).consume(record());
  });
  it.skipIf(HOSTILE_UMASK_DIRECTORY === undefined)("publishes mode 0600 under a hostile umask", async () => {
    process.umask(0o777);
    const value = record("hostile-umask");
    await new FileNonceStore(HOSTILE_UMASK_DIRECTORY!).consume(value);
    expect((await lstat(recordPath(HOSTILE_UMASK_DIRECTORY!, value))).mode & 0o777).toBe(0o600);
    expect((await readdir(join(HOSTILE_UMASK_DIRECTORY!, "records"))).filter((name) => name.endsWith(".tmp"))).toEqual([]);
  });
});

describe.skipIf(CHILD_DIRECTORY !== undefined || HOSTILE_UMASK_DIRECTORY !== undefined)("durable authentication nonce store", () => {
  it("rejects replay across independent store instances", async () => {
    const directory = join(await root(), "nonces");
    await new FileNonceStore(directory).consume(record());
    await expect(new FileNonceStore(directory).consume(record())).rejects.toThrow(/replay|consumed/u);
  });

  it("rejects the same client nonce across overlapping key IDs", async () => {
    const directory = join(await root(), "nonces");
    await new FileNonceStore(directory).consume(record("rotation-nonce", "key-old"));
    await expect(new FileNonceStore(directory).consume(record("rotation-nonce", "key-new"))).rejects.toThrow(/replay|consumed/u);
    expect(recordPath(directory, record("rotation-nonce", "key-old"))).toBe(recordPath(directory, record("rotation-nonce", "key-new")));
  });

  it("scopes nonce uniqueness by client ID", async () => {
    const directory = join(await root(), "nonces");
    await new FileNonceStore(directory).consume(record("shared-nonce", "key-old"));
    await expect(new FileNonceStore(directory).consume({ ...record("shared-nonce", "key-new"), clientId: "other-client" })).resolves.toBeUndefined();
  });

  it("rejects replay across child processes", async () => {
    const directory = join(await root(), "nonces");
    const repository = fileURLToPath(new URL("../../..", import.meta.url));
    const vitest = join(repository, "node_modules", "vitest", "vitest.mjs");
    const run = () => new Promise<number | null>((resolve) => {
      const child = spawn(process.execPath, [vitest, "run", "packages/sidecar/tests/nonce-store.test.ts", "-t", "child-process helper", "--pool=forks", "--maxWorkers=1"], {
        cwd: repository, env: { ...process.env, AGENT_INTEGRITY_NONCE_CHILD_DIRECTORY: directory }, stdio: "ignore",
      });
      child.on("exit", resolve);
    });
    const results = await Promise.all([run(), run()]);
    expect(results.sort()).toEqual([0, 1]);
  }, 15_000);

  it("creates private directories and files", async () => {
    const directory = join(await root(), "nonces");
    await new FileNonceStore(directory).consume(record());
    expect((await lstat(directory)).mode & 0o777).toBe(0o700);
    expect((await lstat(join(directory, "records"))).mode & 0o777).toBe(0o700);
    expect((await lstat(join(directory, "quota"))).mode & 0o777).toBe(0o700);
    expect((await lstat(recordPath(directory, record()))).mode & 0o777).toBe(0o600);
  });

  it("publishes private files independently of process umask", async () => {
    const directory = join(await root(), "nonces");
    const repository = fileURLToPath(new URL("../../..", import.meta.url));
    const vitest = join(repository, "node_modules", "vitest", "vitest.mjs");
    const exitCode = await new Promise<number | null>((resolve) => {
      const child = spawn(process.execPath, [vitest, "run", "packages/sidecar/tests/nonce-store.test.ts", "-t", "hostile umask", "--pool=forks", "--maxWorkers=1"], {
        cwd: repository, env: { ...process.env, AGENT_INTEGRITY_NONCE_HOSTILE_UMASK_DIRECTORY: directory }, stdio: "ignore",
      });
      child.on("exit", resolve);
    });
    expect(exitCode).toBe(0);
  }, 15_000);

  it.each(["file:before-sync", "directory:before-sync"])("fails closed on %s failure, including falsy throws", async (point) => {
    const directory = join(await root(), "nonces");
    let fired = false;
    const store = new FileNonceStore(directory, { faultInjector: (actual) => { if (!fired && actual === point) { fired = true; throw undefined; } } });
    await expect(store.consume(record())).rejects.toBeUndefined();
  });

  it.each([["directory:open", "EPERM"], ["directory:sync", "EACCES"]])("fails closed when %s raises %s", async (point, code) => {
    const directory = join(await root(), "nonces");
    let fired = false;
    const failure = Object.assign(new Error(`${point} denied`), { code });
    const store = new FileNonceStore(directory, { faultInjector: (actual) => { if (!fired && actual === point) { fired = true; throw failure; } } });
    await expect(store.consume(record())).rejects.toBe(failure);
  });

  it("enforces exact record quota across instances", async () => {
    const directory = join(await root(), "nonces");
    await new FileNonceStore(directory, { maxRecords: 2 }).consume(record("one"));
    await new FileNonceStore(directory, { maxRecords: 2 }).consume(record("two"));
    await expect(new FileNonceStore(directory, { maxRecords: 2 }).consume(record("three"))).rejects.toThrow(/limit|quota/u);
  });

  it("allows exactly one concurrent consumer at a one-record quota", async () => {
    const directory = join(await root(), "nonces");
    const attempts = await Promise.allSettled([
      new FileNonceStore(directory, { maxRecords: 1 }).consume(record("one")),
      new FileNonceStore(directory, { maxRecords: 1 }).consume(record("two")),
    ]);
    expect(attempts.filter(({ status }) => status === "fulfilled")).toHaveLength(1);
    expect(attempts.filter(({ status }) => status === "rejected")).toHaveLength(1);
  });

  it("enforces bounded state and closed record parsing", async () => {
    const directory = join(await root(), "nonces");
    const store = new FileNonceStore(directory, { maxStateBytes: 512 });
    await store.consume(record());
    const path = recordPath(directory, record());
    await writeFile(path, `${JSON.stringify({ ...record(), unknown: true })}\n`);
    await expect(new FileNonceStore(directory, { maxStateBytes: 512 }).consume(record())).rejects.toThrow(/invalid|unknown/u);
    await writeFile(path, "x".repeat(513));
    await expect(new FileNonceStore(directory, { maxStateBytes: 512 }).consume(record())).rejects.toThrow(/limit|exceeds/u);
  });

  it("detects root, child, and parent substitution", async () => {
    const grandparent = await root();
    const parent = join(grandparent, "parent");
    const directory = join(parent, "nonces");
    await mkdir(parent, { mode: 0o700 });
    const store = new FileNonceStore(directory);
    await store.consume(record("first"));
    await rename(parent, `${parent}-old`);
    await mkdir(parent, { mode: 0o700 });
    await mkdir(directory, { mode: 0o700 });
    await expect(store.consume(record("second"))).rejects.toThrow(/identity|replaced/u);

    const another = join(await root(), "nonces");
    const fresh = new FileNonceStore(another);
    await fresh.consume(record("first"));
    await rename(join(another, "records"), join(another, "records-old"));
    await mkdir(join(another, "records"), { mode: 0o700 });
    await expect(fresh.consume(record("second"))).rejects.toThrow(/identity|replaced/u);

    const replaced = join(await root(), "nonces");
    await new FileNonceStore(replaced).consume(record("first"));
    await rename(replaced, `${replaced}-old`);
    await mkdir(replaced, { mode: 0o700 });
    await expect(new FileNonceStore(replaced).consume(record("second"))).rejects.toThrow(/identity|replaced/u);
  });

  it("rejects symlink roots, broad roots, and hostile record nodes", async () => {
    const parent = await root();
    const target = join(parent, "target");
    await mkdir(target, { mode: 0o700 });
    const linkRoot = join(parent, "link");
    await symlink(target, linkRoot);
    await expect(new FileNonceStore(linkRoot).consume(record())).rejects.toThrow(/symlink/u);
    await chmod(target, 0o755);
    await expect(new FileNonceStore(target).consume(record())).rejects.toThrow(/mode|permission/u);

    const directory = join(await root(), "nonces");
    const store = new FileNonceStore(directory);
    await store.consume(record("seed"));
    const symlinkRecord = record("symlink-record");
    await symlink(join(directory, "configuration.json"), recordPath(directory, symlinkRecord));
    await expect(store.consume(symlinkRecord)).rejects.toThrow(/symlink/u);
    const hardlinkRecord = record("hardlink-record");
    const hardlinkTarget = join(directory, "records", "untrusted-target");
    await writeFile(hardlinkTarget, "{}\n", { mode: 0o600 });
    await link(hardlinkTarget, recordPath(directory, hardlinkRecord));
    await expect(store.consume(hardlinkRecord)).rejects.toThrow(/one link|exactly one/u);
  });

  it("requires retention beyond the complete skew window", async () => {
    const directory = join(await root(), "nonces");
    await expect(new FileNonceStore(directory, { maximumSkewMs: 60_000 }).consume({ ...record(), retainedUntilMs: record().timestampMs + 60_000 })).rejects.toThrow(/retention/u);
    await expect(new FileNonceStore(directory, { maximumSkewMs: 60_000 }).consume(record())).resolves.toBeUndefined();
    await expect(new FileNonceStore(join(await root(), "invalid-time")).consume({ ...record(), timestampMs: 999_999_999_999 })).rejects.toThrow(/retention|fields/u);
  });

  it("rejects accessor-backed records without execution and keeps filenames opaque", async () => {
    const directory = join(await root(), "nonces");
    const input = { ...record() } as Record<string, unknown>;
    let reads = 0;
    Object.defineProperty(input, "nonce", { enumerable: true, get() { reads += 1; return "changed"; } });
    await expect(new FileNonceStore(directory).consume(input as unknown as NonceRecord)).rejects.toThrow(/invalid nonce record/u);
    expect(reads).toBe(0);
    const store = new FileNonceStore(join(await root(), "opaque"));
    await store.consume(record("private-nonce-value"));
    expect(recordPath(store.directory, record("private-nonce-value"))).not.toContain("private-nonce-value");
    expect(dirname(recordPath(store.directory, record()))).toBe(join(store.directory, "records"));
    expect(await readFile(recordPath(store.directory, record("private-nonce-value")), "utf8")).toContain("private-nonce-value");
  });
});
