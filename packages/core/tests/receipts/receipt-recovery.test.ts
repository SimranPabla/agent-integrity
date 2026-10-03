import { mkdir, mkdtemp, readFile, rename, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  buildReceipt,
  FileReceiptStore,
  ReceiptOutputBoundary,
  verifyTrustedEnvelope,
} from "../../src/index.js";
import { receiptSigningOptions } from "../support/receipt-keys.js";
import { trustedEnvelopeFixture } from "../support/trusted-envelope.js";

async function fixture(runId = "recovery-run", nonce = "recovery-nonce") {
  const { envelope, context } = await trustedEnvelopeFixture();
  const verification = await verifyTrustedEnvelope(envelope, context);
  const inputs = {
    runId,
    envelope,
    verification,
    ...receiptSigningOptions,
    nonce,
    createdAt: new Date("2026-08-02T00:00:00.000Z"),
    expiresAt: new Date("2026-08-02T01:00:00.000Z"),
  };
  return { inputs, receipt: buildReceipt(inputs) };
}

describe("deterministic receipt construction", () => {
  it("reconstructs the identical signed receipt from identical explicit inputs", async () => {
    const { inputs, receipt } = await fixture();
    expect(buildReceipt(inputs)).toEqual(receipt);
    expect(buildReceipt(structuredClone(inputs))).toEqual(receipt);
  });

  it("changes the receipt digest when any bound identity changes", async () => {
    const { inputs, receipt } = await fixture();
    for (const changed of [
      { ...inputs, runId: "different-run" },
      { ...inputs, nonce: "different-nonce" },
      { ...inputs, audience: "different-audience" },
      { ...inputs, expiresAt: new Date("2026-08-02T00:59:59.000Z") },
    ]) {
      expect(buildReceipt(changed).receiptDigest).not.toBe(receipt.receiptDigest);
    }
  });
});

describe("receipt recovery inspection", () => {
  it("requires and preserves one caller-supplied transaction identity", async () => {
    const directory = await mkdtemp(join(tmpdir(), "receipt-recovery-"));
    const store = new FileReceiptStore(join(directory, "store"), { maxRecords: 3 });
    const { receipt } = await fixture();
    await store.issue(receipt, { transactionId: "service-transaction-1" });

    const byDigest = await store.inspectIssuedByDigest(receipt.receiptDigest);
    const byRun = await store.inspectIssuedByRunId(receipt.runId);
    expect(byDigest).toEqual(receipt);
    expect(byRun).toEqual(receipt);
    expect(Object.isFrozen(byDigest)).toBe(true);
    expect(await store.inspectCapacity()).toEqual({ used: 1, maximum: 3 });

    const issuedPath = join(directory, "store", "issued", `${receipt.receiptDigest}.json`);
    expect(JSON.parse(await readFile(issuedPath, "utf8")).transactionId).toBe("service-transaction-1");
    await expect(store.issue(receipt, { transactionId: "different-transaction" })).rejects.toThrow(/transaction|issued|exists/u);
  });

  it("returns undefined only for absent records and rejects malformed stored state", async () => {
    const directory = await mkdtemp(join(tmpdir(), "receipt-inspect-"));
    const storePath = join(directory, "store");
    const store = new FileReceiptStore(storePath);
    const { receipt } = await fixture("inspect-run", "inspect-nonce");
    expect(await store.inspectIssuedByDigest(receipt.receiptDigest)).toBeUndefined();
    await store.issue(receipt, { transactionId: "inspect-transaction" });
    await writeFile(join(storePath, "issued", `${receipt.receiptDigest}.json`), "{}\n");
    await expect(store.inspectIssuedByDigest(receipt.receiptDigest)).rejects.toThrow(/invalid|state/u);
  });

  it("makes consumed and closed terminal states mutually exclusive", async () => {
    const firstRoot = await mkdtemp(join(tmpdir(), "receipt-close-"));
    const firstStore = new FileReceiptStore(join(firstRoot, "store"));
    const { receipt: first } = await fixture("close-first", "close-first-nonce");
    await firstStore.issue(first, { transactionId: "close-transaction" });
    await firstStore.closeIssuedReceipt(first.receiptDigest, {
      transactionId: "close-transaction",
      closedAt: new Date("2026-08-02T00:30:00.000Z"),
      reasonCode: "RECEIPT_RECHECK_REFUSED",
    });
    await expect(firstStore.consume(first, new Date("2026-08-02T00:31:00.000Z"))).rejects.toThrow(/closed/u);

    const secondRoot = await mkdtemp(join(tmpdir(), "receipt-consume-"));
    const secondStore = new FileReceiptStore(join(secondRoot, "store"));
    const { receipt: second } = await fixture("consume-first", "consume-first-nonce");
    await secondStore.issue(second, { transactionId: "consume-transaction" });
    await secondStore.consume(second, new Date("2026-08-02T00:30:00.000Z"));
    expect(await secondStore.inspectConsumed(second.receiptDigest)).toMatchObject({
      transactionId: "consume-transaction",
      consumedAt: "2026-08-02T00:30:00.000Z",
    });
    await expect(secondStore.closeIssuedReceipt(second.receiptDigest, {
      transactionId: "consume-transaction",
      closedAt: new Date("2026-08-02T00:31:00.000Z"),
      reasonCode: "RECEIPT_RECHECK_REFUSED",
    })).rejects.toThrow(/consumed/u);
  });
});

describe("receipt output boundary", () => {
  it("publishes only one safe relative receipt name under a pinned root", async () => {
    const directory = await mkdtemp(join(tmpdir(), "receipt-output-"));
    const outputRoot = join(directory, "outputs");
    await mkdir(outputRoot, { mode: 0o700 });
    const boundary = await ReceiptOutputBoundary.open(outputRoot);
    const store = new FileReceiptStore(join(directory, "store"));
    const { receipt } = await fixture("output-run", "output-nonce");
    await store.issue(receipt, { transactionId: "output-transaction" });
    await expect(store.completeReceiptFile(receipt.receiptDigest, boundary, "receipt.json")).resolves.toEqual(receipt);
    expect(JSON.parse(await readFile(join(outputRoot, "receipt.json"), "utf8"))).toEqual(receipt);
    await expect(store.completeReceiptFile(receipt.receiptDigest, boundary, "receipt.json")).resolves.toEqual(receipt);

    for (const name of ["/tmp/receipt.json", "../receipt.json", "nested/receipt.json", "nested\\receipt.json", ".", ""])
      await expect(store.completeReceiptFile(receipt.receiptDigest, boundary, name)).rejects.toThrow(/relative|filename|output/u);
  });

  it("rejects conflicting output, symlink output, and substituted output roots", async () => {
    const directory = await mkdtemp(join(tmpdir(), "receipt-output-attack-"));
    const outputRoot = join(directory, "outputs");
    await mkdir(outputRoot, { mode: 0o700 });
    const boundary = await ReceiptOutputBoundary.open(outputRoot);
    const store = new FileReceiptStore(join(directory, "store"));
    const { receipt } = await fixture("attack-run", "attack-nonce");
    await store.issue(receipt, { transactionId: "attack-transaction" });

    await writeFile(join(outputRoot, "conflict.json"), "{}\n");
    await expect(store.completeReceiptFile(receipt.receiptDigest, boundary, "conflict.json")).rejects.toThrow(/conflict|equivalent|exists/u);
    await symlink("conflict.json", join(outputRoot, "link.json"));
    await expect(store.completeReceiptFile(receipt.receiptDigest, boundary, "link.json")).rejects.toThrow(/symbolic|regular|conflict/u);

    await rename(outputRoot, `${outputRoot}-old`);
    await mkdir(outputRoot, { mode: 0o700 });
    await expect(store.completeReceiptFile(receipt.receiptDigest, boundary, "after-swap.json")).rejects.toThrow(/identity|changed/u);
  });

  it("recovers byte-equivalently when the caller misses success after output publication", async () => {
    const directory = await mkdtemp(join(tmpdir(), "receipt-output-crash-"));
    const outputRoot = join(directory, "outputs");
    await mkdir(outputRoot, { mode: 0o700 });
    const boundary = await ReceiptOutputBoundary.open(outputRoot);
    let injected = false;
    const storePath = join(directory, "store");
    const faulty = new FileReceiptStore(storePath, {
      faultInjector: (point) => {
        if (!injected && point === "receipt-output:after-publish") {
          injected = true;
          throw new Error("caller missed committed output");
        }
      },
    });
    const { receipt } = await fixture("output-crash", "output-crash-nonce");
    await faulty.issue(receipt, { transactionId: "output-crash-transaction" });
    await expect(faulty.completeReceiptFile(receipt.receiptDigest, boundary, "receipt.json")).rejects.toThrow(/missed committed/u);
    await expect(new FileReceiptStore(storePath).completeReceiptFile(receipt.receiptDigest, boundary, "receipt.json")).resolves.toEqual(receipt);
  });
});
