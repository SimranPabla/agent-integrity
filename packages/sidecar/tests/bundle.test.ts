import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, cp, lstat, mkdir, mkdtemp, readFile, readdir, rename, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalJson, sha256Canonical } from "@agent-integrity/core";
import type { IntegrityEnvelope } from "@agent-integrity/protocol";
import { describe, expect, it } from "vitest";
import {
  assertSafeBundleId,
  openPrivateBundleSnapshot,
  parseCanonicalServiceRequest,
  validateAndSnapshotBundle,
  type BundleLimits,
  type BundleSnapshotOptions,
} from "../src/index.js";

const FIXTURE = fileURLToPath(new URL("fixtures/bundle", import.meta.url));
const NOW = Date.parse("2030-01-01T00:05:00.000Z");
const LIMITS: BundleLimits = {
  maxManifestBytes: 1024 * 1024,
  maxAllowedSourceRoots: 64,
  maxFiles: 10_000,
  maxPathBytes: 1024,
  maxFileBytes: 1024 * 1024,
  maxTotalBytes: 4 * 1024 * 1024,
  maxFutureSkewMs: 60_000,
  maxBundleLifetimeMs: 15 * 60_000,
};

const sha256 = (bytes: Uint8Array): string => createHash("sha256").update(bytes).digest("hex");

function envelope(): IntegrityEnvelope {
  const content = "The approved maintenance window begins at 09:00 UTC.";
  const contentBytes = Buffer.from(content);
  return {
    protocolVersion: "1-alpha",
    policy: {
      version: 1,
      sources: { allowedRoots: ["docs"] },
      decisions: { path: "integrity/decisions.yaml" },
      rules: {
        requireEvidenceFor: ["factual"], contradictions: "review",
        rejectedDecisions: "block", responseMutation: "block", replay: "block",
      },
    },
    response: {
      content,
      sections: [{ sectionId: "answer", substantive: true, byteStart: 0, byteEnd: contentBytes.length, sha256: sha256(contentBytes) }],
    },
    sources: [{
      sourceId: "approved", path: "docs/approved.md", size: 53,
      sha256: "003a0c9c179f9c588d66ab7866582562437188dccded254270df454ea5a0b3d0",
    }],
    decisionRegistryDigest: "44fbe87080e7534ae05e225047dcdc1851e5d3a1e7e45d654d7828a5dd8e0e88",
    decisions: [],
    evidence: [{ evidenceId: "approved-window", sourceId: "approved", anchor: { byteStart: 0, byteEnd: contentBytes.length, sha256: sha256(contentBytes) } }],
    claims: [{ claimId: "window", sectionId: "answer", kind: "factual", decisionIds: [], evidence: [{ evidenceId: "approved-window", role: "supporting", support: "direct" }] }],
  };
}

function request(bundleId = "bundle-1") {
  const body = { serviceProtocolVersion: "1", requestId: "req-1", idempotencyKey: "idem-1", bundleId, envelope: envelope() };
  const bytes = Buffer.from(canonicalJson(body));
  return parseCanonicalServiceRequest(bytes, 1024 * 1024);
}

type Manifest = Record<string, unknown> & {
  files: Array<Record<string, unknown>>;
  evidenceCompleteness: Record<string, unknown>;
  allowedSourceRoots: string[];
};

async function privateTree(path: string): Promise<void> {
  const info = await lstat(path);
  if (info.isDirectory()) {
    await chmod(path, 0o750);
    for (const name of await readdir(path)) await privateTree(join(path, name));
  } else {
    await chmod(path, 0o640);
  }
}

async function setup() {
  const root = await mkdtemp(join(tmpdir(), "sidecar-bundle-"));
  const incomingRoot = join(root, "incoming");
  const snapshotRoot = join(root, "snapshots");
  await mkdir(incomingRoot, { mode: 0o750 });
  await mkdir(snapshotRoot, { mode: 0o700 });
  const bundle = join(incomingRoot, "bundle-1");
  await cp(FIXTURE, bundle, { recursive: true, preserveTimestamps: true });
  await privateTree(bundle);
  return { root, incomingRoot, snapshotRoot, bundle, request: request() };
}

async function manifest(bundle: string): Promise<Manifest> {
  return JSON.parse(await readFile(join(bundle, "manifest.json"), "utf8")) as Manifest;
}

async function writeManifest(bundle: string, value: Manifest, options: { recomputeDigest?: boolean; canonical?: boolean } = {}): Promise<void> {
  const copy = structuredClone(value);
  if (options.recomputeDigest !== false) {
    delete copy.manifestDigest;
    value.manifestDigest = sha256Canonical(copy);
  }
  await writeFile(join(bundle, "manifest.json"), options.canonical === false ? `${JSON.stringify(value, null, 2)}\n` : canonicalJson(value));
  await chmod(join(bundle, "manifest.json"), 0o640);
}

function options(test: Awaited<ReturnType<typeof setup>>, override: Partial<BundleSnapshotOptions> = {}): BundleSnapshotOptions {
  return { request: test.request, incomingRoot: test.incomingRoot, snapshotRoot: test.snapshotRoot, nowMs: NOW, limits: LIMITS, ...override };
}

describe("sidecar evidence-bundle boundary", () => {
  it("copies an exhaustive canonical bundle into a deeply frozen private snapshot", async () => {
    const test = await setup();
    const snapshot = await validateAndSnapshotBundle(options(test));
    expect(snapshot.snapshotId).toMatch(/^[a-f0-9]{64}$/u);
    expect(snapshot.projectRoot).toBe(join(test.snapshotRoot, snapshot.snapshotId, "project"));
    expect(snapshot.policyPath).toBe("integrity/policy.yaml");
    expect(snapshot.files.map(({ path }) => path)).toEqual(["docs/approved.md", "integrity/decisions.yaml", "integrity/policy.yaml", "integrity/trusted-config.json"]);
    expect(Object.isFrozen(snapshot)).toBe(true);
    expect(Object.isFrozen(snapshot.files)).toBe(true);
    expect((await lstat(join(test.snapshotRoot, snapshot.snapshotId))).mode & 0o777).toBe(0o700);
    expect((await lstat(join(snapshot.projectRoot, "docs", "approved.md"))).mode & 0o777).toBe(0o600);
  });

  it.each(["../bundle", "/absolute", "nested/bundle", "nested\\bundle", ".", "..", "https:%2f%2fevil"])("rejects unsafe bundle ID %s", (bundleId) => {
    expect(() => assertSafeBundleId(bundleId)).toThrow(/bundle|identifier/u);
  });

  it.each([
    ["bundleId", "other"], ["requestId", "other"], ["envelopeDigest", "0".repeat(64)],
  ])("rejects a %s binding mismatch", async (field, value) => {
    const test = await setup();
    const data = await manifest(test.bundle);
    data[field] = value;
    await writeManifest(test.bundle, data);
    await expect(validateAndSnapshotBundle(options(test))).rejects.toThrow(/mismatch|binding/u);
  });

  it.each(["root", "evidence", "file"])("rejects unknown fields at the %s level", async (level) => {
    const test = await setup();
    const data = await manifest(test.bundle);
    if (level === "root") data.unknown = true;
    if (level === "evidence") data.evidenceCompleteness.unknown = true;
    if (level === "file") data.files[0]!.unknown = true;
    await writeManifest(test.bundle, data);
    await expect(validateAndSnapshotBundle(options(test))).rejects.toThrow(/manifest|unknown|invalid/u);
  });

  it.each(["envelope", "runId"])("rejects forbidden bundle-owned %s metadata", async (field) => {
    const test = await setup();
    const data = await manifest(test.bundle);
    data[field] = field === "envelope" ? envelope() : "run-before-receipt";
    await writeManifest(test.bundle, data);
    await expect(validateAndSnapshotBundle(options(test))).rejects.toThrow(/unknown|manifest/u);
  });

  it("requires the exact completeness statement", async () => {
    const test = await setup();
    const data = await manifest(test.bundle);
    data.evidenceCompleteness.statement = "partial";
    await writeManifest(test.bundle, data);
    await expect(validateAndSnapshotBundle(options(test))).rejects.toThrow(/completeness|manifest/u);
  });

  it.each([
    ["invalid timestamp", { publishedAt: "2030-01-01" }],
    ["nullable expiry", { expiresAt: null }],
    ["publication at expiry", { publishedAt: "2030-01-01T00:10:01.000Z" }],
    ["collected after publication", { collectedAt: "2030-01-01T00:00:02.000Z" }],
    ["future publication", { publishedAt: "2030-01-01T00:06:00.001Z", expiresAt: "2030-01-01T00:10:01.000Z" }],
    ["expired at equality", { expiresAt: "2030-01-01T00:05:00.000Z" }],
    ["overlong lifetime", { expiresAt: "2030-01-01T00:15:01.001Z" }],
  ])("rejects %s", async (_name, changes) => {
    const test = await setup();
    const data = await manifest(test.bundle);
    for (const [key, value] of Object.entries(changes)) {
      if (key === "collectedAt") data.evidenceCompleteness.collectedAt = value;
      else data[key] = value;
    }
    await writeManifest(test.bundle, data);
    await expect(validateAndSnapshotBundle(options(test))).rejects.toThrow(/time|fresh|expiry|lifetime|manifest/u);
  });

  it.each(["files", "roots"])("requires sorted unique %s", async (kind) => {
    const test = await setup();
    const data = await manifest(test.bundle);
    if (kind === "files") data.files = [data.files[1]!, data.files[0]!, ...data.files.slice(2)];
    else data.allowedSourceRoots = ["docs/sub", "docs"];
    await writeManifest(test.bundle, data);
    await expect(validateAndSnapshotBundle(options(test))).rejects.toThrow(/sorted|root|files|manifest/u);
  });

  it.each(["files", "roots"])("rejects duplicate %s", async (kind) => {
    const test = await setup();
    const data = await manifest(test.bundle);
    if (kind === "files") data.files.splice(1, 0, structuredClone(data.files[0]!));
    else data.allowedSourceRoots = ["docs", "docs"];
    await writeManifest(test.bundle, data);
    await expect(validateAndSnapshotBundle(options(test))).rejects.toThrow(/sorted|unique/u);
  });

  it.each(["../escape", "/absolute", "docs//approved.md", "docs/./approved.md", "docs\\approved.md", "docs/%2e%2e/escape"])("rejects unsafe project path %s", async (path) => {
    const test = await setup();
    const data = await manifest(test.bundle);
    data.files[0]!.path = path;
    await writeManifest(test.bundle, data);
    await expect(validateAndSnapshotBundle(options(test))).rejects.toThrow(/path|traversal/u);
  });

  it.each(["policyPath", "decisionRegistryPath", "trustedConfigPath", "source"])("requires the %s file binding", async (kind) => {
    const test = await setup();
    const data = await manifest(test.bundle);
    const path = kind === "source" ? "docs/approved.md" : String(data[kind]);
    data.files = data.files.filter((entry) => entry.path !== path);
    await writeManifest(test.bundle, data);
    await expect(validateAndSnapshotBundle(options(test))).rejects.toThrow(/required|source|listed|manifest/u);
  });

  it("rejects overlapping allowed roots for one envelope source", async () => {
    const test = await setup();
    const data = await manifest(test.bundle);
    data.allowedSourceRoots = ["docs", "docs/approved.md"];
    await writeManifest(test.bundle, data);
    await expect(validateAndSnapshotBundle(options(test))).rejects.toThrow(/exactly one|root/u);
  });

  it("rejects manifest self-listing, noncanonical bytes, and a bad self-digest", async () => {
    const first = await setup();
    const firstData = await manifest(first.bundle);
    firstData.files.push({ path: "manifest.json", bytes: 0, sha256: "0".repeat(64) });
    firstData.files.sort((left, right) => Buffer.compare(Buffer.from(String(left.path)), Buffer.from(String(right.path))));
    await writeManifest(first.bundle, firstData);
    await expect(validateAndSnapshotBundle(options(first))).rejects.toThrow(/manifest\.json|path/u);

    const second = await setup();
    await writeManifest(second.bundle, await manifest(second.bundle), { canonical: false });
    await expect(validateAndSnapshotBundle(options(second))).rejects.toThrow(/canonical/u);

    const third = await setup();
    const thirdData = await manifest(third.bundle);
    thirdData.manifestDigest = "0".repeat(64);
    await writeManifest(third.bundle, thirdData, { recomputeDigest: false });
    await expect(validateAndSnapshotBundle(options(third))).rejects.toThrow(/digest/u);
  });

  it.each(["extra", "missing", "size", "digest"])("rejects %s file state", async (kind) => {
    const test = await setup();
    const data = await manifest(test.bundle);
    if (kind === "extra") await writeFile(join(test.bundle, "project", "docs", "extra.md"), "extra");
    if (kind === "missing") await rename(join(test.bundle, "project", "docs", "approved.md"), join(test.bundle, "project", "docs", "gone.md"));
    if (kind === "size") data.files[0]!.bytes = 999;
    if (kind === "digest") data.files[0]!.sha256 = "0".repeat(64);
    await writeManifest(test.bundle, data);
    await expect(validateAndSnapshotBundle(options(test))).rejects.toThrow(/extra|missing|size|digest|exhaustive/u);
  });

  it("rejects symlink, hardlink, and nonregular file entries", async () => {
    const symlinkTest = await setup();
    const source = join(symlinkTest.bundle, "project", "docs", "approved.md");
    await rename(source, `${source}.real`);
    await symlink(`${source}.real`, source);
    await expect(validateAndSnapshotBundle(options(symlinkTest))).rejects.toThrow(/symlink|regular/u);

    const hardlinkTest = await setup();
    const hardlinkSource = join(hardlinkTest.bundle, "project", "docs", "approved.md");
    await import("node:fs/promises").then(({ link }) => link(hardlinkSource, `${hardlinkSource}.other`));
    await expect(validateAndSnapshotBundle(options(hardlinkTest))).rejects.toThrow(/link|exhaustive/u);

    const fifoTest = await setup();
    const fifo = join(fifoTest.bundle, "project", "docs", "approved.md");
    await rename(fifo, `${fifo}.old`);
    const result = spawnSync("mkfifo", [fifo]);
    if (result.status !== 0) throw new Error("mkfifo unavailable for test");
    await expect(validateAndSnapshotBundle(options(fifoTest))).rejects.toThrow(/regular/u);
  });

  it("rejects broad incoming permissions", async () => {
    const test = await setup();
    await chmod(join(test.bundle, "project", "docs", "approved.md"), 0o666);
    await expect(validateAndSnapshotBundle(options(test))).rejects.toThrow(/permission|mode/u);
  });

  it.each([
    ["manifest", { maxManifestBytes: 128 }],
    ["roots", { maxAllowedSourceRoots: 0 }],
    ["files", { maxFiles: 3 }],
    ["path", { maxPathBytes: 8 }],
    ["file bytes", { maxFileBytes: 52 }],
    ["total bytes", { maxTotalBytes: 394 }],
  ])("enforces the configured %s limit", async (_name, changed) => {
    const test = await setup();
    await expect(validateAndSnapshotBundle(options(test, { limits: { ...LIMITS, ...changed } }))).rejects.toThrow(/limit|maximum|bytes|files|roots|path/u);
  });

  it.each([
    { maxManifestBytes: 1024 * 1024 + 1 },
    { maxAllowedSourceRoots: 65 },
    { maxFiles: 10_001 },
    { maxPathBytes: 1025 },
    { maxFutureSkewMs: 60_001 },
    { maxBundleLifetimeMs: 15 * 60_000 + 1 },
  ])("rejects configuration above a hard ceiling: %o", async (changed) => {
    const test = await setup();
    await expect(validateAndSnapshotBundle(options(test, { limits: { ...LIMITS, ...changed } }))).rejects.toThrow(/hard maximum|limit/u);
  });

  it("bounds manifest JSON complexity before canonical processing", async () => {
    const test = await setup();
    const path = join(test.bundle, "manifest.json");
    const raw = await readFile(path, "utf8");
    const marker = ',"version":"1"}';
    const nested = `${'{"next":'.repeat(70)}{}${"}".repeat(70)}`;
    await writeFile(path, raw.replace(marker, `,"unknown":${nested}${marker}`));
    await chmod(path, 0o640);
    await expect(validateAndSnapshotBundle(options(test))).rejects.toThrow(/complexity|depth|limit/u);
  });

  it("bounds exhaustive traversal including extra directories", async () => {
    const test = await setup();
    for (let index = 0; index < 30; index += 1) await mkdir(join(test.bundle, "project", "docs", `extra-${index}`), { mode: 0o750 });
    await expect(validateAndSnapshotBundle(options(test, { limits: { ...LIMITS, maxFiles: 4, maxAllowedSourceRoots: 1 } }))).rejects.toThrow(/entry limit/u);
  });

  it("rejects accessor-backed options without executing them", async () => {
    const test = await setup();
    const hostile = { ...options(test) } as Record<string, unknown>;
    let accessed = false;
    Object.defineProperty(hostile, "incomingRoot", { enumerable: true, get() { accessed = true; return test.incomingRoot; } });
    await expect(validateAndSnapshotBundle(hostile as unknown as BundleSnapshotOptions)).rejects.toThrow(/options.*invalid/u);
    expect(accessed).toBe(false);
  });

  it("detects file mutation during copy", async () => {
    const test = await setup();
    let fired = false;
    await expect(validateAndSnapshotBundle(options(test, {
      faultInjector: async (point, path) => {
        if (!fired && point === "file:after-read" && path?.endsWith("approved.md")) {
          fired = true;
          await writeFile(path, "X".repeat(53));
        }
      },
    }))).rejects.toThrow(/changed|mutation|digest/u);
  });

  it("detects incoming bundle-root substitution before publication", async () => {
    const test = await setup();
    let fired = false;
    await expect(validateAndSnapshotBundle(options(test, {
      faultInjector: async (point) => {
        if (!fired && point === "bundle:before-final-identity") {
          fired = true;
          await rename(test.bundle, `${test.bundle}-old`);
          await mkdir(test.bundle, { mode: 0o750 });
        }
      },
    }))).rejects.toThrow(/identity|replaced/u);
  });

  it("accepts an identical destination and rejects a corrupted collision", async () => {
    const test = await setup();
    const first = await validateAndSnapshotBundle(options(test));
    const second = await validateAndSnapshotBundle(options(test));
    expect(second.snapshotId).toBe(first.snapshotId);
    await writeFile(join(first.projectRoot, "docs", "approved.md"), "corrupt");
    await expect(validateAndSnapshotBundle(options(test))).rejects.toThrow(/snapshot|digest|size/u);
  });

  it("rejects a symlink collision without overwriting it", async () => {
    const seed = await setup();
    const snapshotId = (await validateAndSnapshotBundle(options(seed))).snapshotId;
    const test = await setup();
    const outside = join(test.root, "outside");
    await mkdir(outside, { mode: 0o700 });
    const collision = join(test.snapshotRoot, snapshotId);
    await symlink(outside, collision);
    await expect(validateAndSnapshotBundle(options(test))).rejects.toThrow(/symlink|directory/u);
    expect((await lstat(collision)).isSymbolicLink()).toBe(true);
  });

  it("reopens the private snapshot after the incoming bundle expires", async () => {
    const test = await setup();
    const first = await validateAndSnapshotBundle(options(test));
    const recovered = await openPrivateBundleSnapshot({ snapshotRoot: test.snapshotRoot, snapshotId: first.snapshotId, limits: LIMITS });
    expect(recovered).toEqual(first);
    await expect(validateAndSnapshotBundle(options(test, { nowMs: Date.parse("2030-01-01T00:10:01.000Z") }))).rejects.toThrow(/expired|expiry|fresh/u);
  });
});
