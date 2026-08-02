import { verifyEnvelope } from "../../packages/core/dist/index.js";
import { releaseVerifiedResponse } from "../../packages/sdk/dist/index.js";

const envelope = {
  protocolVersion: "1-alpha",
  policy: { version: 1, sources: { allowedRoots: ["docs"] }, decisions: { path: "integrity/decisions.yaml" }, rules: { requireEvidenceFor: ["factual"], contradictions: "review", rejectedDecisions: "block", responseMutation: "block", replay: "block" } },
  response: { content: "Original response", sections: [{ sectionId: "answer", substantive: true }] },
  sources: [{ sourceId: "source", path: "docs/source.md", sha256: "c".repeat(64), size: 16 }],
  decisions: [],
  evidence: [{ evidenceId: "evidence", sourceId: "source" }],
  claims: [{ claimId: "claim", sectionId: "answer", kind: "factual", evidence: [{ evidenceId: "evidence", role: "supporting", support: "direct" }] }],
};

const verification = verifyEnvelope(envelope);
const changed = { ...envelope, response: { ...envelope.response, content: "Changed response" } };
const result = releaseVerifiedResponse({ envelope: changed, verification });
console.log(JSON.stringify(result, null, 2));
if (result.status !== "BLOCKED" || "response" in result) process.exitCode = 1;
