import { execFile } from "node:child_process";
import { spawn } from "node:child_process";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { beforeAll, describe, expect, it } from "vitest";
import { createReceipt, verifyEnvelope } from "@agent-integrity/core";
import type { AlphaIntegrityReceipt, IntegrityEnvelope } from "@agent-integrity/protocol";
import { validEnvelope } from "../../core/tests/support/valid-envelope.js";

const execFileAsync = promisify(execFile);
const root = new URL("../../..", import.meta.url).pathname;
const cli = join(root, "packages/cli/dist/cli.js");

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
    const envelope = validEnvelope();
    envelope.response.content = "PRIVATE SOURCE-LIKE RESPONSE";
    const result = await run("verify", { envelope });
    expect(result.code).toBe(0);
    expect(result.output).toMatchObject({ status: "PASS", protocolVersion: "1-alpha", findings: [] });
    expect(JSON.stringify(result.output)).not.toContain("PRIVATE SOURCE-LIKE RESPONSE");
  });

  it("uses stable REVIEW and BLOCKED exit codes", async () => {
    const reviewEnvelope = validEnvelope();
    reviewEnvelope.claims[0]!.evidence[0] = {
      ...reviewEnvelope.claims[0]!.evidence[0]!, support: "ambiguous",
    };
    const blockedEnvelope = validEnvelope();
    blockedEnvelope.claims = [];
    expect((await run("verify", { envelope: reviewEnvelope })).code).toBe(2);
    expect((await run("verify", { envelope: blockedEnvelope })).code).toBe(3);
  });

  it("rechecks and inspects a receipt without exposing the envelope", async () => {
    const directory = await mkdtemp(join(tmpdir(), "integrity-cli-"));
    const envelope = validEnvelope();
    const verification = verifyEnvelope(envelope);
    const receiptPath = join(directory, "receipt.json");
    const receipt = await createReceipt({
      runId: "cli-test", path: receiptPath, envelope, verification,
      createdAt: new Date("2026-08-02T00:00:00.000Z"),
      expiresAt: new Date("2026-08-03T00:00:00.000Z"),
    });
    const recheck = await run("recheck", {
      receipt, envelope, now: "2026-08-02T01:00:00.000Z",
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
