import { verifyEnvelope } from "../../packages/core/dist/index.js";
import { releaseVerifiedResponse } from "../../packages/sdk/dist/index.js";

const envelope = {
  protocolVersion: "1-alpha",
  policy: { version: 1, sources: { allowedRoots: ["docs"] }, decisions: { path: "integrity/decisions.yaml" }, rules: { requireEvidenceFor: ["factual"], contradictions: "review", rejectedDecisions: "block", responseMutation: "block", replay: "block" } },
  response: { content: "Original response", sections: [{ sectionId: "answer", substantive: true, byteStart: 0, byteEnd: 17, sha256: "d874e9ec7af7a8d905750e12e764804ec3aee19b31a4dc3c5aa9554ae1c2712f" }] },
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
