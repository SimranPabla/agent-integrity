import { createHash } from "node:crypto";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { buildReceipt, verifyTrustedEnvelope } from "../../src/index.js";
import { FileReceiptStore, RECEIPT_STORE_LOCK_AUTHORIZER } from "../../src/receipts/file-receipt-store.js";
import { receiptSigningOptions } from "../support/receipt-keys.js";
import { trustedEnvelopeFixture } from "../support/trusted-envelope.js";

const roots: string[] = [];
afterEach(async () => { await Promise.all(roots.splice(0).map(root => rm(root, { recursive: true, force: true }))); });
const hash = (value: string) => createHash("sha256").update(value).digest("hex");
const ownership = () => ({ ownerToken: "root-owner", storeGeneration: "generation-1", rootIdentityDigest: "a".repeat(64), [RECEIPT_STORE_LOCK_AUTHORIZER]: () => {} });
async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "task8-core-")); roots.push(root);
  const { envelope, context } = await trustedEnvelopeFixture();
  const receipt = buildReceipt({ runId: "task8-run", nonce: "task8-nonce", envelope, verification: await verifyTrustedEnvelope(envelope, context), ...receiptSigningOptions,
    createdAt: new Date("2026-08-02T00:00:00.000Z"), expiresAt: new Date("2026-08-02T01:00:00.000Z") });
  const directory = join(root, "store");
  const store = new FileReceiptStore(directory, { maxRecords: 3, lockOwnership: ownership() });
  return { directory, receipt, store };
}
async function snapshot(directory: string) {
  const result: Record<string, string> = {};
  for (const kind of ["transactions", "quota", "runs", "nonces", "issued"])
    for (const name of await readdir(join(directory, kind))) result[kind + "/" + name] = await readFile(join(directory, kind, name), "utf8");
  return result;
}

describe("Task8 exact issuance completion and validated evidence", () => {
  for (const phase of ["transaction", "quota", "run", "nonce", "issued"])
    for (const boundary of ["after-publish", "before-directory-sync"]) {
      it("completes the original transaction after " + phase + ":" + boundary, async () => {
        const { directory, receipt, store } = await fixture();
        let fired = false;
        const faulty = new FileReceiptStore(directory, { maxRecords: 3, lockOwnership: ownership(), faultInjector: point => {
          if (!fired && point === phase + ":" + boundary) { fired = true; throw new Error("publication sync crash"); }
        } });
        await expect(faulty.issue(receipt, { transactionId: "original-tx" })).rejects.toThrow(/crash|quota reservation failed/);
        expect(fired).toBe(true);
        const before = await snapshot(directory);
        await store.completePreparedIssue(receipt, { transactionId: "original-tx" });
        const after = await snapshot(directory);
        for (const [name, bytes] of Object.entries(before)) expect(after[name]).toBe(bytes);
        const inspected = await store.inspectIssuedRecordByDigest(receipt.receiptDigest);
        expect(inspected).toMatchObject({ transactionId: "original-tx", receipt, runId: receipt.runId, nonce: receipt.nonce });
        expect(await store.inspectIssuedRecordByRunId(receipt.runId)).toEqual(inspected);
        expect(await store.inspectCapacity()).toEqual({ used: 1, maximum: 3 });
        await store.completePreparedIssue(receipt, { transactionId: "original-tx" });
        expect(await snapshot(directory)).toEqual(after);
        await expect(store.completePreparedIssue(receipt, { transactionId: "other-tx" })).rejects.toThrow();
      });
    }
  it("requires live authorization and permits one exact initial issue", async () => {
    const { directory, receipt, store } = await fixture();
    await expect(new FileReceiptStore(directory).completePreparedIssue(receipt, { transactionId: "tx" })).rejects.toThrow(/ownership|authoriz|live/);
    const dead = new FileReceiptStore(directory, { lockOwnership: { ...ownership(), [RECEIPT_STORE_LOCK_AUTHORIZER]: () => { throw new Error("expired authority"); } } });
    await expect(dead.completePreparedIssue(receipt, { transactionId: "tx" })).rejects.toThrow(/expired/);
    await store.completePreparedIssue(receipt, { transactionId: "tx" });
    expect(await store.inspectIssuedByDigest(receipt.receiptDigest)).toEqual(receipt);
  });
  it("rejects missing intent and orphaned or contradictory pointers without mutation", async () => {
    const { directory, receipt, store } = await fixture();
    await store.issue(receipt, { transactionId: "tx" });
    await rm(join(directory, "transactions", hash(receipt.receiptDigest) + ".json"));
    const before = await snapshot(directory);
    await expect(store.completePreparedIssue(receipt, { transactionId: "tx" })).rejects.toThrow();
    expect(await snapshot(directory)).toEqual(before);
    await expect(store.inspectIssuedRecordByDigest(receipt.receiptDigest)).rejects.toThrow();
    await rm(join(directory, "issued", receipt.receiptDigest + ".json"));
    await expect(store.inspectIssuedByRunId(receipt.runId)).rejects.toThrow();
    await expect(store.inspectIssuedRecordByDigest(receipt.receiptDigest)).rejects.toThrow();
  });
  it("rejects mismatched quota slots and nonce pointers", async () => {
    const { directory, receipt, store } = await fixture();
    await store.issue(receipt, { transactionId: "tx" });
    const path = join(directory, "nonces", hash(receipt.nonce) + ".json");
    const value = JSON.parse(await readFile(path, "utf8"));
    await writeFile(path, JSON.stringify({ ...value, quotaSlot: (value.quotaSlot + 1) % 3 }));
    const before = await snapshot(directory);
    await expect(store.completePreparedIssue(receipt, { transactionId: "tx" })).rejects.toThrow();
    await expect(store.inspectIssuedRecordByRunId(receipt.runId)).rejects.toThrow();
    expect(await snapshot(directory)).toEqual(before);
  });
  it("preserves original close timestamp and rejects conflicting terminal evidence", async () => {
    const { directory, receipt, store } = await fixture();
    await store.issue(receipt, { transactionId: "tx" });
    const faulty = new FileReceiptStore(directory, { lockOwnership: ownership(), maxRecords: 3, faultInjector: point => { if (point === "closed:after-publish") throw new Error("close crash"); } });
    const closedAt = new Date("2026-08-02T00:20:00.000Z");
    await expect(faulty.closeIssuedReceipt(receipt.receiptDigest, { transactionId: "tx", closedAt, reasonCode: "RECEIPT_RECHECK_REFUSED" })).rejects.toThrow(/crash/);
    const closed = await store.inspectClosed(receipt.receiptDigest);
    expect(closed).toMatchObject({ receipt, transactionId: "tx", closedAt: closedAt.toISOString(), reasonCode: "RECEIPT_RECHECK_REFUSED" });
    expect(Object.isFrozen(closed?.receipt)).toBe(true);
    await expect(store.consume(receipt, new Date())).rejects.toThrow(/closed/);
    const issued = JSON.parse(await readFile(join(directory, "issued", receipt.receiptDigest + ".json"), "utf8"));
    await writeFile(join(directory, "consumed", receipt.receiptDigest + ".json"), JSON.stringify({ ...issued, consumedAt: closedAt.toISOString() }));
    await expect(store.inspectConsumed(receipt.receiptDigest)).rejects.toThrow();
    await expect(store.inspectClosed(receipt.receiptDigest)).rejects.toThrow();
  });
  for (const missing of ["quota", "runs", "nonces", "issued"] as const) {
    it("fails closed on unexplained missing " + missing + " without deleting surviving evidence", async () => {
      const { directory, receipt, store } = await fixture();
      await store.issue(receipt, { transactionId: "tx" });
      const name = (await readdir(join(directory, missing)))[0]!;
      await rm(join(directory, missing, name));
      const before = await snapshot(directory);
      if (missing === "issued") {
        // A complete intent/quota/run/nonce prefix is an explainable interrupted publication.
        await store.completePreparedIssue(receipt, { transactionId: "tx" });
        const after = await snapshot(directory);
        for (const [path, bytes] of Object.entries(before)) expect(after[path]).toBe(bytes);
      } else {
        await expect(store.completePreparedIssue(receipt, { transactionId: "tx" })).rejects.toThrow();
        expect(await snapshot(directory)).toEqual(before);
      }
    });
  }
  it("rejects duplicate quota ownership and marker path substitutions", async () => {
    const { directory, receipt, store } = await fixture();
    await store.issue(receipt, { transactionId: "tx" });
    const name = (await readdir(join(directory, "quota")))[0]!;
    const quota = JSON.parse(await readFile(join(directory, "quota", name), "utf8"));
    const otherSlot = (quota.quotaSlot + 1) % 3;
    await writeFile(join(directory, "quota", hash(String(otherSlot)) + ".json"), JSON.stringify({ ...quota, quotaSlot: otherSlot }));
    const before = await snapshot(directory);
    await expect(store.completePreparedIssue(receipt, { transactionId: "tx" })).rejects.toThrow();
    await expect(store.inspectIssuedRecordByDigest(receipt.receiptDigest)).rejects.toThrow();
    expect(await snapshot(directory)).toEqual(before);
  });
  it("cross-checks consumed evidence against issued payload and bindings", async () => {
    const { directory, receipt, store } = await fixture();
    await store.issue(receipt, { transactionId: "tx" });
    const at = new Date("2026-08-02T00:20:00.000Z");
    await store.consume(receipt, at);
    expect(await store.inspectConsumed(receipt.receiptDigest)).toMatchObject({ transactionId: "tx", consumedAt: at.toISOString() });
    await expect(store.consume(receipt, at)).rejects.toThrow(/consumed/);
    const path = join(directory, "consumed", receipt.receiptDigest + ".json");
    const consumed = JSON.parse(await readFile(path, "utf8"));
    await writeFile(path, JSON.stringify({ ...consumed, transactionId: "different-tx" }));
    await expect(store.inspectConsumed(receipt.receiptDigest)).rejects.toThrow();
  });
});
