import { describe, expect, it } from "vitest";
import { verifyEnvelope } from "../../src/index.js";

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
});
