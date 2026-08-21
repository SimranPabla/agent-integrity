import { describe, expect, test } from "vitest";
import { provenanceFrom } from "../../scripts/release-status.mjs";

const manifest = { owner: "SimranPabla", repository: "agent-integrity", tag: "v0.1.0-alpha.0", commit: "a".repeat(40), workflowFile: "npm-release.yml" };

function attestation(workflow: Record<string, string>) {
  const statement = { predicate: { buildDefinition: { externalParameters: { workflow } } } };
  return { bundle: { dsseEnvelope: { payload: Buffer.from(JSON.stringify(statement)).toString("base64") } } };
}

describe("npm provenance binding", () => {
  test("binds a cryptographically verified tag workflow to the resolved release commit", () => {
    const result = provenanceFrom([attestation({
      repository: "https://github.com/SimranPabla/agent-integrity",
      path: ".github/workflows/npm-release.yml",
      ref: "refs/tags/v0.1.0-alpha.0",
    })], manifest, true);
    expect(result).toEqual({ verified: true, repository: "SimranPabla/agent-integrity", commit: manifest.commit, workflowFile: "npm-release.yml", ref: "refs/tags/v0.1.0-alpha.0" });
  });

  test("rejects provenance from another ref or workflow", () => {
    expect(provenanceFrom([attestation({ repository: "https://github.com/SimranPabla/agent-integrity", path: ".github/workflows/other.yml", ref: "refs/heads/main" })], manifest, true)).toBeUndefined();
  });
});
