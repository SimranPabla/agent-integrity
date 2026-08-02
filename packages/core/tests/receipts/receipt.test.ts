import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createReceipt, recheckReceipt, verifyEnvelope } from "../../src/index.js";
import { validEnvelope } from "../support/valid-envelope.js";

describe("alpha receipts", () => {
  it("persists an explicitly unsigned content-bound receipt without overwriting", async () => {
    const directory = await mkdtemp(join(tmpdir(), "integrity-receipt-"));
    const path = join(directory, "run-1.json");
    const envelope = validEnvelope();
    const verification = verifyEnvelope(envelope);
    const receipt = await createReceipt({
      runId: "run-1",
      path,
      envelope,
      verification,
      createdAt: new Date("2026-08-02T00:00:00.000Z"),
      expiresAt: new Date("2026-08-02T01:00:00.000Z"),
    });

    expect(receipt.signature).toEqual({ status: "unsigned" });
    expect(receipt.envelopeDigest).toBe(verification.envelopeDigest);
    expect(JSON.parse(await readFile(path, "utf8"))).toEqual(receipt);
    await expect(createReceipt({
      runId: "run-1",
      path,
      envelope,
      verification,
      createdAt: new Date("2026-08-02T00:00:00.000Z"),
      expiresAt: new Date("2026-08-02T01:00:00.000Z"),
    })).rejects.toThrow(/already exists/u);
  });

  it("rejects duplicate run IDs even when a different receipt filename is supplied", async () => {
    const directory = await mkdtemp(join(tmpdir(), "integrity-receipt-"));
    const envelope = validEnvelope();
    const verification = verifyEnvelope(envelope);
    const common = {
      runId: "same-run",
      envelope,
      verification,
      createdAt: new Date("2026-08-02T00:00:00.000Z"),
      expiresAt: new Date("2026-08-02T01:00:00.000Z"),
      runRegistryDirectory: directory,
    };
    await createReceipt({ ...common, path: join(directory, "first.json") });
    await expect(createReceipt({ ...common, path: join(directory, "second.json") }))
      .rejects.toThrow(/run ID already exists/u);
  });

  it("passes a fresh receipt only when all live bound content is unchanged", async () => {
    const directory = await mkdtemp(join(tmpdir(), "integrity-receipt-"));
    const envelope = validEnvelope();
    const verification = verifyEnvelope(envelope);
    const receipt = await createReceipt({
      runId: "run-2",
      path: join(directory, "run-2.json"),
      envelope,
      verification,
      createdAt: new Date("2026-08-02T00:00:00.000Z"),
      expiresAt: new Date("2026-08-02T01:00:00.000Z"),
    });
    const result = recheckReceipt({ receipt, envelope, now: new Date("2026-08-02T00:30:00.000Z") });
    expect(result.status).toBe("PASS");
  });

  it("blocks expired receipts", async () => {
    const directory = await mkdtemp(join(tmpdir(), "integrity-receipt-"));
    const envelope = validEnvelope();
    const receipt = await createReceipt({
      runId: "run-3",
      path: join(directory, "run-3.json"),
      envelope,
      verification: verifyEnvelope(envelope),
      createdAt: new Date("2026-08-02T00:00:00.000Z"),
      expiresAt: new Date("2026-08-02T01:00:00.000Z"),
    });
    const result = recheckReceipt({ receipt, envelope, now: new Date("2026-08-02T01:00:00.000Z") });
    expect(result.status).toBe("BLOCKED");
    expect(result.findings.map((finding) => finding.code)).toContain("receipt.expired");
  });
});
