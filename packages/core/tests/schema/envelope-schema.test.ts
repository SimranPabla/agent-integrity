import { describe, expect, it } from "vitest";
import { verifyEnvelope } from "../../src/index.js";
import { readFile } from "node:fs/promises";
import { validEnvelope as completeEnvelope } from "../support/valid-envelope.js";

function validEnvelope(): Record<string, unknown> {
  return {
    protocolVersion: "1-alpha",
    policy: {
      version: 1,
      sources: { allowedRoots: ["sources"] },
      decisions: { path: "decisions.yaml" },
      rules: {
        requireEvidenceFor: ["factual"],
        contradictions: "block",
        rejectedDecisions: "block",
        responseMutation: "block",
        replay: "block",
      },
    },
    response: { content: "", sections: [] },
    sources: [],
    decisions: [],
    evidence: [],
    claims: [],
  };
}

describe("strict envelope runtime schema", () => {
  it("blocks unknown fields", () => {
    const envelope = validEnvelope();
    envelope.untrustedOverride = true;
    expect(verifyEnvelope(envelope as never)).toMatchObject({
      status: "BLOCKED",
      findings: [{ code: "checker.failure" }],
    });
  });

  it("blocks permissive or incomplete policy objects", () => {
    const envelope = validEnvelope();
    (envelope.policy as Record<string, unknown>).rules = {
      requireEvidenceFor: [],
      contradictions: "ignore",
      rejectedDecisions: "allow",
      responseMutation: "allow",
      replay: "allow",
    };
    expect(verifyEnvelope(envelope as never).status).toBe("BLOCKED");
  });

  it("blocks mistyped nested fields instead of relying on TypeScript", () => {
    const envelope = validEnvelope();
    envelope.response = {
      content: "claim",
      sections: [{ sectionId: "s1", substantive: "false", byteStart: 0, byteEnd: 1, sha256: "a".repeat(64) }],
    };
    expect(verifyEnvelope(envelope as never).status).toBe("BLOCKED");
  });

  it("blocks oversized collections before verification work", () => {
    const envelope = validEnvelope();
    envelope.sources = Array.from({ length: 10_001 }, (_, index) => ({
      sourceId: `source-${index}`,
      path: `source-${index}.txt`,
      sha256: "0".repeat(64),
      size: 0,
    }));
    expect(verifyEnvelope(envelope as never).status).toBe("BLOCKED");
  });

  it.each([
    ["supporting disclosed", { role: "supporting", support: "direct", disclosed: true }],
    ["contradictory support", { role: "contradictory", support: "direct" }],
    ["contextual support", { role: "contextual", support: "ambiguous" }],
    ["contextual disclosed", { role: "contextual", disclosed: false }],
  ])("keeps runtime role metadata rules aligned for %s", async (_name, metadata) => {
    const envelope = completeEnvelope();
    envelope.claims[0]!.evidence[0] = { evidenceId: "evidence-1", ...metadata } as never;
    expect(verifyEnvelope(envelope).status).toBe("BLOCKED");
    const schema = JSON.parse(await readFile(new URL("../../../../schemas/integrity-envelope.schema.json", import.meta.url), "utf8"));
    expect(JSON.stringify(schema.$defs.claimEvidence.allOf)).toContain(`\"${metadata.role}\"`);
  });

  it("documents character-vs-UTF-8-byte limits and enforces the byte limit at runtime", async () => {
    const schema = JSON.parse(await readFile(new URL("../../../../schemas/integrity-envelope.schema.json", import.meta.url), "utf8"));
    expect(schema.$defs.response.description).toMatch(/UTF-8 bytes.*cannot express/u);
    expect(schema.$defs.response.properties.content.maxLength).toBeUndefined();
    const envelope = completeEnvelope();
    envelope.response = { content: "é".repeat(8_388_609), sections: [] };
    expect(verifyEnvelope(envelope).status).toBe("BLOCKED");
  });
});
