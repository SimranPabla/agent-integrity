import { createHash } from "node:crypto";
import { mkdtemp, mkdir, writeFile, readFile, readdir, rm, access } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it, vi } from "vitest";
import { releaseVerifiedReceipt } from "../../../sdk/src/release.js";
import { buildReceipt, FileReceiptStore, verifyTrustedEnvelope } from "@agent-integrity/core";
import { receiptSigningOptions, receiptTrust } from "../support/receipt-keys.js";
import type { IntegrityEnvelope } from "@agent-integrity/protocol";
import type { TrustedVerificationContext } from "../../src/verify-trusted.js";
import { validEnvelope } from "../support/valid-envelope.js";

type Fixture = { directory: string; envelope: IntegrityEnvelope; context: TrustedVerificationContext };
const setupSteps = ["sdk-root", "project-root", "docs", "integrity", "source", "registry"] as const;
type SetupStep = typeof setupSteps[number];
type Controls = {
  roots?: string[];
  checkpoint?: (step: SetupStep) => Promise<void>;
  remove?: (root: string) => Promise<void>;
};
const digest = (bytes: string | Buffer): string => createHash("sha256").update(bytes).digest("hex");
const removeRoot = (root: string): Promise<void> => rm(root, { recursive: true, force: true });

// Capture exact ownership before any subsequent awaited provisioning.
async function withOwnedFixture(body: (fixture: Fixture) => Promise<void>, controls: Controls = {}): Promise<void> {
  const owned: string[] = [];
  const checkpoint = controls.checkpoint ?? (async () => {});
  const allocate = async (prefix: string): Promise<string> => {
    const root = await mkdtemp(join(tmpdir(), prefix));
    owned.push(root);
    controls.roots?.push(root);
    return root;
  };
  let failed = false;
  let failure: unknown;
  try {
    const directory = await allocate("receipt-capture-sdk-");
    await checkpoint("sdk-root");
    const projectRoot = await allocate("receipt-capture-project-");
    await checkpoint("project-root");
    await mkdir(join(projectRoot, "docs"));
    await checkpoint("docs");
    await mkdir(join(projectRoot, "integrity"));
    await checkpoint("integrity");
    const bytes = Buffer.from("0123456789", "utf8");
    await writeFile(join(projectRoot, "docs", "source.md"), bytes);
    await checkpoint("source");
    const registry = "version: 1\nevents: []\n";
    await writeFile(join(projectRoot, "integrity", "decisions.yaml"), registry);
    await checkpoint("registry");
    const base = validEnvelope();
    await body({
      directory,
      context: { projectRoot, allowedRoots: ["docs"], decisionRegistryPath: "integrity/decisions.yaml", trustedPolicy: base.policy },
      envelope: {
        ...base,
        decisionRegistryDigest: digest(registry),
        sources: [{ sourceId: "source-1", path: "docs/source.md", size: bytes.length, sha256: digest(bytes) }],
        evidence: [{ evidenceId: "evidence-1", sourceId: "source-1", anchor: { byteStart: 0, byteEnd: 4, sha256: digest("0123") } }],
      },
    });
  } catch (error) {
    failed = true;
    failure = error;
  }
  // Schedule all removals even when one throws synchronously or rejects.
  const cleanup = await Promise.allSettled(owned.map(root => Promise.resolve().then(() => (controls.remove ?? removeRoot)(root))));
  const cleanupFailures = cleanup.flatMap(result => result.status === "rejected" ? [result.reason] : []);
  if (cleanupFailures.length > 0) throw new AggregateError(failed ? [failure, ...cleanupFailures] : cleanupFailures, "fixture cleanup failed");
  if (failed) throw failure;
}

async function expectRemoved(roots: string[]): Promise<void> {
  for (const root of roots) await expect(access(root)).rejects.toMatchObject({ code: "ENOENT" });
}

it.each(setupSteps)("cleans exact owned roots after rejected setup at %s", async step => {
  const sentinel = await mkdtemp(join(tmpdir(), "receipt-capture-sentinel-"));
  try {
    await writeFile(join(sentinel, "unchanged"), "unrelated fixture");
    const roots: string[] = [];
    const failure = new Error("rejected setup at " + step);
    const body = vi.fn(async () => {});
    await expect(withOwnedFixture(body, {
      roots,
      checkpoint: async current => { if (current === step) throw failure; },
    })).rejects.toBe(failure);
    expect(roots).toHaveLength(step === "sdk-root" ? 1 : 2);
    expect(body).not.toHaveBeenCalled();
    await expectRemoved(roots);
    expect(await readFile(join(sentinel, "unchanged"), "utf8")).toBe("unrelated fixture");
    expect(await readdir(sentinel)).toEqual(["unchanged"]);
  } finally {
    await removeRoot(sentinel);
  }
});

it("cleans exact roots and preserves a rejected body failure", async () => {
  const roots: string[] = [];
  const failure = new Error("body rejected");
  await expect(withOwnedFixture(async () => { throw failure; }, { roots })).rejects.toBe(failure);
  expect(roots).toHaveLength(2);
  await expectRemoved(roots);
});

it.each([false, true])("attempts every cleanup and reports failures with setup failure=%s", async setupFails => {
  const roots: string[] = [];
  const attempted: string[] = [];
  const setupFailure = new Error("setup rejected");
  const cleanupFailure = new Error("first cleanup rejected");
  try {
    await expect(withOwnedFixture(async () => {}, {
      roots,
      checkpoint: async step => { if (setupFails && step === "project-root") throw setupFailure; },
      remove: async root => {
        attempted.push(root);
        if (root === roots[0]) throw cleanupFailure;
        await removeRoot(root);
      },
    })).rejects.toMatchObject({ errors: setupFails ? [setupFailure, cleanupFailure] : [cleanupFailure] });
    expect(roots).toHaveLength(2);
    expect(attempted).toEqual(roots);
    const [first, second] = roots;
    if (!first || !second) throw new Error("expected both owned roots");
    await access(first); // Deliberately rejected removal is surfaced, not mislabeled clean.
    await expectRemoved([second]);
  } finally {
    await Promise.all(roots.map(removeRoot)); // Exact roots only; injection is confined to the exercised lifecycle.
  }
  await expectRemoved(roots);
});

it("real store signed SDK PASS releases exact bytes once and preserves the consumed marker on replay", async () => {
  const roots: string[] = [];
  await withOwnedFixture(async ({ directory, envelope, context }) => {
    const verification = await verifyTrustedEnvelope(envelope, context);
    expect(verification.status).toBe("PASS");
    const receipt = buildReceipt({
      ...receiptSigningOptions,
      runId: "capture-sdk-run",
      nonce: "capture-sdk-nonce",
      envelope,
      verification,
      createdAt: new Date("2026-08-02T00:00:00.000Z"),
      expiresAt: new Date("2026-08-02T01:00:00.000Z"),
    });
    const receiptStore = new FileReceiptStore(join(directory, "store"));
    await receiptStore.issue(receipt, { transactionId: "capture-sdk-transaction" });
    const consume = vi.spyOn(receiptStore, "consume");
    const options = {
      envelope, context, verification, receipt, receiptStore,
      trust: { ...receiptTrust, trustedPolicy: context.trustedPolicy },
      now: new Date("2026-08-02T00:30:00.000Z"),
    };
    const first = await releaseVerifiedReceipt(options);
    expect(first.status).toBe("PASS");
    if (first.status !== "PASS") throw new Error("signed release refused");
    expect(Buffer.from(first.response, "utf8")).toEqual(Buffer.from(envelope.response.content, "utf8"));
    expect(consume).toHaveBeenCalledOnce();
    expect(consume.mock.calls[0]![0]).not.toBe(receipt);
    const markerPath = join(directory, "store", "consumed", receipt.receiptDigest + ".json");
    const marker = await readFile(markerPath);
    expect(JSON.parse(marker.toString())).toMatchObject({
      transactionId: "capture-sdk-transaction", consumedAt: options.now.toISOString(),
    });
    expect(await readdir(join(directory, "store", "issued"))).toHaveLength(1);
    expect(await readdir(join(directory, "store", "consumed"))).toHaveLength(1);
    expect(await readdir(join(directory, "store", "closed"))).toHaveLength(0);
    const retry = await releaseVerifiedReceipt(options);
    expect(retry.status).toBe("BLOCKED");
    expect(retry).not.toHaveProperty("response");
    expect(retry.verification.findings.map(finding => finding.code)).toContain("receipt.replayed");
    expect(await readFile(markerPath)).toEqual(marker);
    expect(await readdir(join(directory, "store", "consumed"))).toHaveLength(1);
    expect(consume).toHaveBeenCalledTimes(2); // second attempt refuses; no second publication
  }, { roots });
  expect(roots).toHaveLength(2);
  await expectRemoved(roots);
});
