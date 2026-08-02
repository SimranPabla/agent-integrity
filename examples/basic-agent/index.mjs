import { verifyEnvelope } from "../../packages/core/dist/index.js";
import { AgentIntegritySession, releaseVerifiedResponse } from "../../packages/sdk/dist/index.js";

const policy = {
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
};

const session = new AgentIntegritySession(policy)
  .setResponse("The maintenance window begins at 09:00 UTC.", [
    { sectionId: "answer", substantive: true, byteStart: 0, byteEnd: 43, sha256: "540beff0286b1ba21c45be4113a48f85ca13cb1b6b4b1f9ef9de06bf08238f6a" },
  ])
  .addSource({
    sourceId: "maintenance-policy",
    path: "docs/maintenance.md",
    sha256: "a".repeat(64),
    size: 42,
  })
  .addEvidence({ evidenceId: "maintenance-window", sourceId: "maintenance-policy" })
  .addClaim({
    claimId: "window-start",
    sectionId: "answer",
    kind: "factual",
    evidence: [{ evidenceId: "maintenance-window", role: "supporting", support: "direct" }],
  });

const envelope = session.buildEnvelope();
const verification = verifyEnvelope(envelope);
const release = releaseVerifiedResponse({ envelope, verification });
console.log(JSON.stringify(release, null, 2));
if (release.status !== "PASS") process.exitCode = 1;
