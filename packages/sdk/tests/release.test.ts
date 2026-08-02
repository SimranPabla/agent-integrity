import { describe, expect, it } from "vitest";
import { verifyEnvelope } from "@agent-integrity/core";
import { PROTOCOL_VERSION, type IntegrityEnvelope } from "@agent-integrity/protocol";
import { releaseVerifiedResponse } from "../src/release.js";

function validEnvelope(): IntegrityEnvelope {
  return {
    protocolVersion: PROTOCOL_VERSION,
    policy: {
      version: 1,
      sources: { allowedRoots: ["docs"] },
      decisions: { path: "integrity/decisions.yaml" },
      rules: {
        requireEvidenceFor: ["factual", "recommendation"],
        contradictions: "review",
        rejectedDecisions: "block",
        responseMutation: "block",
        replay: "block",
      },
    },
    response: { content: "Supported response", sections: [{ sectionId: "answer", substantive: true, byteStart: 0, byteEnd: 18, sha256: "a31069ff26ded3cd55c0d40ebaa3430097950a210b8caaece07b27dedbb92766" }] },
    sources: [{ sourceId: "source-1", path: "docs/source.md", sha256: "a".repeat(64), size: 10 }],
    decisions: [],
    evidence: [{ evidenceId: "evidence-1", sourceId: "source-1" }],
    claims: [{
      claimId: "claim-1",
      sectionId: "answer",
      kind: "factual",
      evidence: [{ evidenceId: "evidence-1", role: "supporting", support: "direct" }],
    }],
  };
}

describe("releaseVerifiedResponse", () => {
  it("releases only the exact response bound to a PASS result", () => {
    const envelope = validEnvelope();
    const verification = verifyEnvelope(envelope);
    expect(releaseVerifiedResponse({ envelope, verification })).toEqual({
      status: "PASS",
      response: "Supported response",
      verification,
    });
  });

  it("releases nothing for REVIEW", () => {
    const base = validEnvelope();
    const envelope = {
      ...base,
      claims: [{ ...base.claims[0]!, evidence: [{ evidenceId: "evidence-1", role: "supporting" as const, support: "ambiguous" as const }] }],
    };
    const verification = verifyEnvelope(envelope);
    const result = releaseVerifiedResponse({ envelope, verification });
    expect(result.status).toBe("REVIEW");
    expect("response" in result).toBe(false);
  });

  it("releases nothing for BLOCKED", () => {
    const base = validEnvelope();
    const envelope = { ...base, claims: [{ ...base.claims[0]!, evidence: [] }] };
    const verification = verifyEnvelope(envelope);
    const result = releaseVerifiedResponse({ envelope, verification });
    expect(result.status).toBe("BLOCKED");
    expect("response" in result).toBe(false);
  });

  it("blocks post-verification response mutation", () => {
    const envelope = validEnvelope();
    const verification = verifyEnvelope(envelope);
    const mutated = { ...envelope, response: { content: "Changed after checking", sections: [{ sectionId: "answer", substantive: true, byteStart: 0, byteEnd: 22, sha256: "d7e39934bbd672eec72ac901869071c5a98498bd14bb5a6b0596ab954ece672c" }] } };
    const result = releaseVerifiedResponse({ envelope: mutated, verification });
    expect(result.status).toBe("BLOCKED");
    expect(result.verification.findings[0]?.code).toBe("release.verification_mismatch");
    expect("response" in result).toBe(false);
  });

  it("fails closed when supplied malformed input", () => {
    const envelope = validEnvelope();
    const verification = verifyEnvelope(envelope);
    const result = releaseVerifiedResponse({ envelope: null as never, verification });
    expect(result.status).toBe("BLOCKED");
    expect("response" in result).toBe(false);
  });
});
