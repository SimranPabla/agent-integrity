import { execFile } from "node:child_process";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { beforeAll, describe, expect, it } from "vitest";
import { createReceipt, verifyTrustedEnvelope } from "@agent-integrity/core";
import type { AlphaIntegrityReceipt, IntegrityEnvelope } from "@agent-integrity/protocol";
import { validEnvelope } from "../../core/tests/support/valid-envelope.js";

const execFileAsync = promisify(execFile);
const root = new URL("../../..", import.meta.url).pathname;
const cli = join(root, "packages/cli/dist/cli.js");
const digest = (value: string): string => createHash("sha256").update(value).digest("hex");

async function trustedFixture(envelope = validEnvelope()) {
  const projectRoot = await mkdtemp(join(tmpdir(), "integrity-cli-source-"));
  await mkdir(join(projectRoot, "docs"));
  const content = "0123456789";
  await writeFile(join(projectRoot, "docs", "source.md"), content);
  (envelope as any).sources = [{ sourceId: "source-1", path: "docs/source.md", size: 10, sha256: digest(content) }];
  (envelope as any).evidence = [{ evidenceId: "evidence-1", sourceId: "source-1", anchor: { byteStart: 0, byteEnd: 4, sha256: digest("0123") } }];
  return { envelope, context: { projectRoot, allowedRoots: ["docs"] } };
}

async function run(command: string, input: unknown): Promise<{ code: number; output: any; stderr: string }> {
  return runRaw(command, JSON.stringify(input));
}

async function runRaw(command: string, input: string): Promise<{ code: number; output: any; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cli, command], { cwd: root, stdio: ["pipe", "pipe", "pipe"] });
    let output = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (chunk: string) => { output += chunk; });
    child.stderr.setEncoding("utf8").on("data", (chunk: string) => { stderr += chunk; });
    child.on("error", reject);
    child.on("close", (code) => resolve({ code: code ?? 1, output: JSON.parse(output), stderr }));
    child.stdin.end(input);
  });
}

beforeAll(async () => {
  await execFileAsync("npm", ["run", "build"], { cwd: root });
});

describe("integrity CLI", () => {
  it("validates a strict YAML policy", async () => {
    const policy = [
      "version: 1", "sources:", "  allowedRoots: [docs/]", "decisions:",
      "  path: integrity/decisions.yaml", "rules:",
      "  requireEvidenceFor: [factual, recommendation]", "  contradictions: review",
      "  rejectedDecisions: block", "  responseMutation: block", "  replay: block", "",
    ].join("\n");
    const result = await run("validate-policy", { policy });
    expect(result).toMatchObject({ code: 0, output: { ok: true, policy: { version: 1 } }, stderr: "" });
  });

  it("verifies an envelope and returns only integrity metadata", async () => {
    const { envelope, context } = await trustedFixture();
    envelope.response.content = "PRIVATE SOURCE-LIKE RESPONSE";
    envelope.response.sections = [{ sectionId: "answer", substantive: true, byteStart: 0, byteEnd: 28, sha256: "cd1545015ecb32d3597ba7f161f36cd11f3365bf30c55b9400aa037e3cdc0472" }];
    const result = await run("verify", { envelope, context });
    expect(result.code).toBe(0);
    expect(result.output).toMatchObject({ status: "PASS", protocolVersion: "1-alpha", findings: [] });
    expect(JSON.stringify(result.output)).not.toContain("PRIVATE SOURCE-LIKE RESPONSE");
  });

  it("uses stable REVIEW and BLOCKED exit codes", async () => {
    const review = await trustedFixture();
    const reviewEnvelope = review.envelope;
    reviewEnvelope.claims[0]!.evidence[0] = {
      ...reviewEnvelope.claims[0]!.evidence[0]!, support: "ambiguous",
    };
    const blocked = await trustedFixture();
    const blockedEnvelope = blocked.envelope;
    blockedEnvelope.claims = [];
    expect((await run("verify", { envelope: reviewEnvelope, context: review.context })).code).toBe(2);
    expect((await run("verify", { envelope: blockedEnvelope, context: blocked.context })).code).toBe(3);
  });

  it("rechecks and inspects a receipt without exposing the envelope", async () => {
    const directory = await mkdtemp(join(tmpdir(), "integrity-cli-"));
    const trusted = await trustedFixture();
    const { envelope, context } = trusted;
    const verification = await verifyTrustedEnvelope(envelope, context);
    const receiptPath = join(directory, "receipt.json");
    const receipt = await createReceipt({
      runId: "cli-test", path: receiptPath, envelope, verification,
      context,
      createdAt: new Date("2026-08-02T00:00:00.000Z"),
      expiresAt: new Date("2026-08-03T00:00:00.000Z"),
    });
    const recheck = await run("recheck", {
      receipt, envelope, context, now: "2026-08-02T01:00:00.000Z",
    });
    expect(recheck).toMatchObject({ code: 0, output: { status: "PASS" }, stderr: "" });

    const inspect = await run("inspect-receipt", { receipt });
    expect(inspect.code).toBe(0);
    expect(inspect.output).toMatchObject({
      validDigest: true, runId: "cli-test", status: "PASS", signatureStatus: "unsigned",
    });
    expect(JSON.stringify(inspect.output)).not.toContain("sources");
    expect(JSON.parse(await readFile(receiptPath, "utf8"))).toEqual(receipt);
  });

  it("fails closed for malformed JSON and unknown commands", async () => {
    const malformed = await runRaw("verify", "{");
    expect(malformed.code).toBe(1);
    expect(malformed.output).toMatchObject({ error: { code: "cli.invalid_input" } });
    expect((await run("unknown", {}))).toMatchObject({
      code: 1, output: { error: { code: "cli.unknown_command" } }, stderr: "",
    });
  });
});
