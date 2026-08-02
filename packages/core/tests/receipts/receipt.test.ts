import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createReceipt, FileReceiptStore, recheckTrustedReceipt, verifyTrustedEnvelope } from "../../src/index.js";
import { trustedEnvelopeFixture } from "../support/trusted-envelope.js";
import { receiptSigner, receiptSigningOptions, receiptTrust } from "../support/receipt-keys.js";

describe("signed alpha receipts", () => {
  it("persists a producer-authenticated content-bound receipt without overwriting", async () => {
    const directory = await mkdtemp(join(tmpdir(), "integrity-receipt-"));
    const path = join(directory, "run-1.json");
    const receiptStore = new FileReceiptStore(join(directory, "store"));
    const { envelope, context } = await trustedEnvelopeFixture();
    const verification = await verifyTrustedEnvelope(envelope, context);
    const receipt = await createReceipt({
      runId: "run-1",
      path,
      envelope,
      verification,
      context,
      ...receiptSigningOptions,
      createdAt: new Date("2026-08-02T00:00:00.000Z"),
      expiresAt: new Date("2026-08-02T01:00:00.000Z"),
      receiptStore,
    });

    expect(receipt.signature.algorithm).toBe("Ed25519");
    expect(receipt.signature.keyId).toBe(receiptSigner.keyId);
    expect(receipt.envelopeDigest).toBe(verification.envelopeDigest);
    expect(JSON.parse(await readFile(path, "utf8"))).toEqual(receipt);
    await expect(createReceipt({
      runId: "run-1",
      path,
      envelope,
      verification,
      context,
      ...receiptSigningOptions,
      createdAt: new Date("2026-08-02T00:00:00.000Z"),
      expiresAt: new Date("2026-08-02T01:00:00.000Z"),
      receiptStore,
    })).rejects.toThrow(/already exists/u);
  });

  it("rejects duplicate run IDs even when a different receipt filename is supplied", async () => {
    const directory = await mkdtemp(join(tmpdir(), "integrity-receipt-"));
    const { envelope, context } = await trustedEnvelopeFixture();
    const verification = await verifyTrustedEnvelope(envelope, context);
    const common = {
      runId: "same-run",
      envelope,
      verification,
      context,
      createdAt: new Date("2026-08-02T00:00:00.000Z"),
      expiresAt: new Date("2026-08-02T01:00:00.000Z"),
      receiptStore: new FileReceiptStore(join(directory, "store")),
      ...receiptSigningOptions,
    };
    await createReceipt({ ...common, path: join(directory, "first.json") });
    await expect(createReceipt({ ...common, path: join(directory, "second.json") }))
      .rejects.toThrow(/run ID already exists/u);
  });

  it("passes a fresh receipt only when all live bound content is unchanged", async () => {
    const directory = await mkdtemp(join(tmpdir(), "integrity-receipt-"));
    const { envelope, context } = await trustedEnvelopeFixture();
    const verification = await verifyTrustedEnvelope(envelope, context);
    const receiptStore = new FileReceiptStore(join(directory, "store"));
    const receipt = await createReceipt({
      runId: "run-2",
      path: join(directory, "run-2.json"),
      envelope,
      verification,
      context,
      ...receiptSigningOptions,
      createdAt: new Date("2026-08-02T00:00:00.000Z"),
      expiresAt: new Date("2026-08-02T01:00:00.000Z"),
      receiptStore,
    });
    const result = await recheckTrustedReceipt({ trust: receiptTrust, receipt, envelope, context, receiptStore, now: new Date("2026-08-02T00:30:00.000Z") });
    expect(result.status).toBe("PASS");
  });

  it("blocks expired receipts", async () => {
    const directory = await mkdtemp(join(tmpdir(), "integrity-receipt-"));
    const { envelope, context } = await trustedEnvelopeFixture();
    const verification = await verifyTrustedEnvelope(envelope, context);
    const receiptStore = new FileReceiptStore(join(directory, "store"));
    const receipt = await createReceipt({
      runId: "run-3",
      path: join(directory, "run-3.json"),
      envelope,
      verification,
      context,
      ...receiptSigningOptions,
      createdAt: new Date("2026-08-02T00:00:00.000Z"),
      expiresAt: new Date("2026-08-02T01:00:00.000Z"),
      receiptStore,
    });
    const result = await recheckTrustedReceipt({ trust: receiptTrust, receipt, envelope, context, receiptStore, now: new Date("2026-08-02T01:00:00.000Z") });
    expect(result.status).toBe("BLOCKED");
    expect(result.findings.map((finding) => finding.code)).toContain("receipt.expired");
  });

  it("allows exactly one concurrent consumer and rejects copied receipt replay", async () => {
    const directory = await mkdtemp(join(tmpdir(), "integrity-consume-"));
    const receiptStore = new FileReceiptStore(join(directory, "store"));
    const { envelope, context } = await trustedEnvelopeFixture();
    const verification = await verifyTrustedEnvelope(envelope, context);
    const receipt = await createReceipt({ runId: "one-use", path: join(directory, "receipt.json"), envelope, verification, context, receiptStore, ...receiptSigningOptions, createdAt: new Date("2026-08-02T00:00:00.000Z"), expiresAt: new Date("2026-08-02T01:00:00.000Z") });
    const options = { trust: receiptTrust, receipt: structuredClone(receipt), envelope, context, receiptStore, now: new Date("2026-08-02T00:30:00.000Z") };
    const results = await Promise.all([recheckTrustedReceipt(options), recheckTrustedReceipt(options)]);
    expect(results.map((result) => result.status).sort()).toEqual(["BLOCKED", "PASS"]);
    expect(results.flatMap((result) => result.findings.map((finding) => finding.code))).toContain("receipt.replayed");
  });

  it("preserves consumed state after the store is reopened", async () => {
    const directory = await mkdtemp(join(tmpdir(), "integrity-restored-"));
    const storePath = join(directory, "store");
    const { envelope, context } = await trustedEnvelopeFixture();
    const verification = await verifyTrustedEnvelope(envelope, context);
    const receipt = await createReceipt({ runId: "restored", path: join(directory, "receipt.json"), envelope, verification, context, receiptStore: new FileReceiptStore(storePath), ...receiptSigningOptions, createdAt: new Date("2026-08-02T00:00:00.000Z"), expiresAt: new Date("2026-08-02T01:00:00.000Z") });
    expect((await recheckTrustedReceipt({ trust: receiptTrust, receipt, envelope, context, receiptStore: new FileReceiptStore(storePath), now: new Date("2026-08-02T00:30:00.000Z") })).status).toBe("PASS");
    const replay = await recheckTrustedReceipt({ trust: receiptTrust, receipt, envelope, context, receiptStore: new FileReceiptStore(storePath), now: new Date("2026-08-02T00:31:00.000Z") });
    expect(replay.status).toBe("BLOCKED");
    expect(replay.findings.map((finding) => finding.code)).toContain("receipt.replayed");
  });

  it("rolls back registry issuance when the receipt output cannot be written", async () => {
    const directory = await mkdtemp(join(tmpdir(), "integrity-rollback-"));
    const receiptStore = new FileReceiptStore(join(directory, "store"));
    const path = join(directory, "receipt.json");
    await import("node:fs/promises").then(({ writeFile }) => writeFile(path, "occupied"));
    const { envelope, context } = await trustedEnvelopeFixture();
    const verification = await verifyTrustedEnvelope(envelope, context);
    const base = { runId: "retryable", path, envelope, verification, context, receiptStore, ...receiptSigningOptions, createdAt: new Date("2026-08-02T00:00:00.000Z"), expiresAt: new Date("2026-08-02T01:00:00.000Z") };
    await expect(createReceipt(base)).rejects.toThrow(/receipt already exists/u);
    await import("node:fs/promises").then(({ unlink }) => unlink(path));
    await expect(createReceipt(base)).resolves.toMatchObject({ runId: "retryable" });
  });
});
