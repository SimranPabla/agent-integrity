import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createReceipt, recheckReceipt, verifyEnvelope } from "../../src/index.js";
import { validEnvelope } from "../support/valid-envelope.js";

describe("receipt replay and mutation resistance", () => {
  it("blocks replay against a changed response", async () => {
    const directory = await mkdtemp(join(tmpdir(), "integrity-replay-"));
    const envelope = validEnvelope();
    const receipt = await createReceipt({
      runId: "run-replay",
      path: join(directory, "receipt.json"),
      envelope,
      verification: verifyEnvelope(envelope),
      createdAt: new Date("2026-08-02T00:00:00.000Z"),
      expiresAt: new Date("2026-08-02T01:00:00.000Z"),
    });
    const changed = { ...envelope, response: { ...envelope.response, content: `${envelope.response.content}!` } };
    const result = recheckReceipt({ receipt, envelope: changed, now: new Date("2026-08-02T00:30:00.000Z") });
    expect(result.status).toBe("BLOCKED");
    expect(result.findings.map((finding) => finding.code)).toContain("receipt.subject_changed");
  });

  it("blocks a modified receipt", async () => {
    const directory = await mkdtemp(join(tmpdir(), "integrity-replay-"));
    const envelope = validEnvelope();
    const receipt = await createReceipt({
      runId: "run-edit",
      path: join(directory, "receipt.json"),
      envelope,
      verification: verifyEnvelope(envelope),
      createdAt: new Date("2026-08-02T00:00:00.000Z"),
      expiresAt: new Date("2026-08-02T01:00:00.000Z"),
    });
    const edited = { ...receipt, runId: "attacker-run" };
    const result = recheckReceipt({ receipt: edited, envelope, now: new Date("2026-08-02T00:30:00.000Z") });
    expect(result.status).toBe("BLOCKED");
    expect(result.findings.map((finding) => finding.code)).toContain("receipt.mutated");
  });
});
