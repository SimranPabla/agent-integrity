import { createHash } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it, vi } from "vitest";
import { sha256Canonical } from "@agent-integrity/core";
import { verifyTrustedEnvelope } from "../../core/src/verify-trusted.js";
import { validEnvelope } from "../../core/tests/support/valid-envelope.js";
import { releaseVerifiedResponse } from "../src/release.js";

const seam = vi.hoisted(() => ({ collect: vi.fn() }));
vi.mock("../../core/src/sources/collect-source.js", () => ({ collectSourceBytes: seam.collect }));
vi.mock("@agent-integrity/core", async (original) => ({
  ...await original<object>(),
  verifyTrustedEnvelope: (await import("../../core/src/verify-trusted.js")).verifyTrustedEnvelope,
}));
const hash = (bytes: string | Buffer) => createHash("sha256").update(bytes).digest("hex");
const registry = "version: 1\nevents: []\n";
const source = "source text";
const allocated: string[] = [];
afterEach(async () => { for (const root of allocated.splice(0)) await rm(root, { recursive: true, force: true }); });
function fixture() {
  const envelope: any = validEnvelope();
  envelope.decisionRegistryDigest = hash(registry);
  envelope.sources[0] = { sourceId: "source-1", path: "docs/source.md", size: source.length, sha256: hash(source) };
  envelope.evidence[0].anchor = { byteStart: 0, byteEnd: 6, sha256: hash("source") };
  const context: any = { projectRoot: "/virtual", allowedRoots: ["docs"], decisionRegistryPath: "integrity/decisions.yaml", trustedPolicy: envelope.policy, maxSourceBytes: 100, maxTotalSourceBytes: 100 };
  seam.collect.mockImplementation(async (options) => {
    const bytes = Buffer.from(options.sourcePath === "integrity/decisions.yaml" ? registry : source);
    if (bytes.length > options.maxBytes) throw new Error("collection limit");
    return { path: options.sourcePath, bytes, size: bytes.length, sha256: hash(bytes) };
  });
  return { envelope, context };
}
function pauseRegistry() {
  const backend = seam.collect.getMockImplementation()!;
  let resume!: () => void;
  let reached!: () => void;
  const entered = new Promise<void>((resolve) => { reached = resolve; });
  const gate = new Promise<void>((resolve) => { resume = resolve; });
  seam.collect.mockImplementationOnce(async (options) => { reached(); await gate; return backend(options); });
  return { entered, resume };
}
function mutate(envelope: any, context: any) {
  envelope.response.content = "Unchecked replacement";
  envelope.response.sections[0].sha256 = "0".repeat(64);
  envelope.claims[0].evidence = [];
  envelope.evidence[0].anchor.sha256 = "0".repeat(64);
  envelope.sources[0].path = "elsewhere.md";
  envelope.sources[0].sha256 = "0".repeat(64);
  envelope.policy.sources.allowedRoots[0] = "elsewhere";
  envelope.policy.rules.requireEvidenceFor = [];
  envelope.policy.decisions.path = "elsewhere.yaml";
  context.projectRoot = "/changed";
  context.allowedRoots[0] = "elsewhere";
  context.decisionRegistryPath = "elsewhere.yaml";
  context.maxSourceBytes = 1;
  context.maxTotalSourceBytes = 1;
}
describe("plain release entry capture", () => {
  it.each([
    ["response", (e: any) => { e.response.content = "unchecked"; }],
    ["claims", (e: any) => { e.claims[0].evidence = []; }],
    ["evidence", (e: any) => { e.evidence[0].anchor.sha256 = "0".repeat(64); }],
    ["sources", (e: any) => { e.sources[0].path = "changed.md"; }],
    ["policy", (e: any) => { e.policy.rules.contradictions = "block"; }],
    ["roots", (_e: any, c: any) => { c.allowedRoots[0] = "changed"; }],
    ["registry path", (_e: any, c: any) => { c.decisionRegistryPath = "changed.yaml"; }],
    ["project root", (_e: any, c: any) => { c.projectRoot = "/changed"; }],
    ["source ceiling", (_e: any, c: any) => { c.maxSourceBytes = 1; }],
    ["total ceiling", (_e: any, c: any) => { c.maxTotalSourceBytes = 1; }],
    ["trusted policy replacement", (_e: any, c: any) => { c.trustedPolicy = null; }],
  ])("isolates in-flight %s mutation without rereading caller data", async (_name, change) => {
    const { envelope, context } = fixture();
    const verification = await verifyTrustedEnvelope(envelope, context);
    const barrier = pauseRegistry();
    const pending = releaseVerifiedResponse({ envelope, context, verification });
    await barrier.entered;
    (change as (e: any, c: any) => void)(envelope, context);
    barrier.resume();
    expect(await pending).toEqual({ status: "PASS", response: "Supported response", verification });
  });
  it("blocks a valid rehashed replacement paired with stale verification; independently reverified bytes pass", async () => {
    const { envelope, context } = fixture();
    const old = await verifyTrustedEnvelope(envelope, context);
    const content = "New supported response";
    envelope.response.content = content;
    envelope.response.sections[0].byteEnd = Buffer.byteLength(content);
    envelope.response.sections[0].sha256 = hash(content);
    const stale = await releaseVerifiedResponse({ envelope, context, verification: old });
    expect(stale.status).toBe("BLOCKED"); expect(stale).not.toHaveProperty("response");
    const verification = await verifyTrustedEnvelope(envelope, context);
    expect(verification.status).toBe("PASS");
    expect(await releaseVerifiedResponse({ envelope, context, verification })).toEqual({ status: "PASS", response: content, verification });
  });
  it("accepts frozen/null-prototype inputs, shared policy and undefined optional context ceilings", async () => {
    const { envelope, context } = fixture();
    function prepare(value: any): any {
      if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
      for (const key of Object.keys(value)) value[key] = prepare(value[key]);
      if (!Array.isArray(value)) Object.setPrototypeOf(value, null);
      return Object.freeze(value);
    }
    context.maxSourceBytes = undefined; context.maxTotalSourceBytes = undefined;
    prepare(envelope); prepare(context);
    const verification = prepare(await verifyTrustedEnvelope(envelope, context));
    expect(verification.status).toBe("PASS");
    const options = Object.freeze({ envelope, context, verification });
    expect(await releaseVerifiedResponse(options)).toEqual({ status: "PASS", response: "Supported response", verification });
  });
  it("does not mutate or freeze caller objects, or traverse signed-only capabilities", async () => {
    const { envelope, context } = fixture();
    const verification = await verifyTrustedEnvelope(envelope, context);
    const before = sha256Canonical({ envelope, context, verification });
    const callback = vi.fn();
    const options: any = { envelope, context, verification, now: new Date(), receiptStore: { callback } };
    Object.defineProperty(options, "trust", { get: callback });
    expect((await releaseVerifiedResponse(options)).status).toBe("PASS");
    expect(sha256Canonical({ envelope, context, verification })).toBe(before);
    expect(Object.isFrozen(options)).toBe(false); expect(Object.isFrozen(envelope.response)).toBe(false);
    expect(callback).not.toHaveBeenCalled();
  });
  it.each(["envelope", "verification", "context"])("rejects %s option accessors without invocation", async (key) => {
    const { envelope, context } = fixture();
    const verification = await verifyTrustedEnvelope(envelope, context);
    const getter = vi.fn(() => ({ envelope, context, verification }[key]));
    const options: any = { envelope, context, verification };
    Object.defineProperty(options, key, { get: getter, enumerable: true });
    const result = await releaseVerifiedResponse(options);
    expect(result.status).toBe("BLOCKED"); expect(result).not.toHaveProperty("response");
    expect(getter).not.toHaveBeenCalled();
  });
  it.each(["hidden", "getter", "map", "undefined", "symbol", "hole"])("fails closed on preexisting %s without laundering or calling methods", async (kind) => {
    const { envelope, context } = fixture();
    const verification: any = await verifyTrustedEnvelope(envelope, context);
    const sentinel = vi.fn(() => "never");
    if (kind === "hidden") Object.defineProperty(envelope.response, "hidden", { value: "bad" });
    if (kind === "getter") Object.defineProperty(envelope.response, "content", { get: sentinel, enumerable: true });
    if (kind === "map") envelope.sources.map = sentinel;
    if (kind === "undefined") verification.optional = undefined;
    if (kind === "symbol") context[Symbol("bad")] = 1;
    if (kind === "hole") delete envelope.sources[0];
    const direct = await verifyTrustedEnvelope(envelope, context);
    if (kind !== "undefined") expect(direct.status).toBe("BLOCKED");
    const result = await releaseVerifiedResponse({ envelope, context, verification });
    expect(result.status).toBe("BLOCKED"); expect(result).not.toHaveProperty("response");
    expect(sentinel).not.toHaveBeenCalled();
  });
  it("holds REVIEW, BLOCKED and source exceptions without response", async () => {
    for (const mode of ["review", "blocked", "exception"]) {
      const { envelope, context } = fixture();
      if (mode === "review") envelope.claims[0].evidence[0].support = "ambiguous";
      if (mode === "blocked") envelope.claims[0].evidence = [];
      if (mode === "exception") seam.collect.mockImplementation(async () => { throw new Error("source failed"); });
      const verification = await verifyTrustedEnvelope(envelope, context);
      const result = await releaseVerifiedResponse({ envelope, context, verification });
      expect(result.status).toBe(mode === "review" ? "REVIEW" : "BLOCKED");
      expect(result).not.toHaveProperty("response");
    }
  });
  it("binds every nested value and top-level options replacement before the first await", async () => {
    const { envelope, context } = fixture();
    const verification: any = await verifyTrustedEnvelope(envelope, context);
    expect(verification.status).toBe("PASS");
    const expected = { status: "PASS", response: envelope.response.content, verification: { ...verification, findings: [...verification.findings] } };
    const options: any = { envelope, context, verification };
    const barrier = pauseRegistry();
    const pending = releaseVerifiedResponse(options);
    await barrier.entered;
    mutate(envelope, context);
    verification.status = "BLOCKED";
    verification.envelopeDigest = "0".repeat(64);
    verification.findings.push({ code: "changed", severity: "blocked", message: "changed" });
    options.envelope = null; options.context = null; options.verification = null;
    barrier.resume();
    expect(await pending).toEqual(expected);
    expect(Object.isFrozen(envelope)).toBe(false);
    expect(Object.isFrozen(context)).toBe(false);
  });
  it("direct core binds its pre-await digest, source paths, policy and budgets", async () => {
    const { envelope, context } = fixture();
    const digest = sha256Canonical(envelope);
    const barrier = pauseRegistry();
    const pending = verifyTrustedEnvelope(envelope, context);
    await barrier.entered;
    mutate(envelope, context);
    barrier.resume();
    expect(await pending).toMatchObject({ status: "PASS", envelopeDigest: digest });
    expect(seam.collect.mock.calls.at(-1)?.[0]).toMatchObject({ projectRoot: "/virtual", allowedRoots: ["docs"], sourcePath: "docs/source.md", maxBytes: 100 });
  });
  it("still blocks actual source-file mutation while registry collection is paused", async () => {
    const { envelope, context } = fixture();
    const root = await mkdtemp(join(tmpdir(), "agent-integrity-immutable-")); allocated.push(root);
    await mkdir(join(root, "docs")); await mkdir(join(root, "integrity"));
    await writeFile(join(root, "docs/source.md"), source);
    await writeFile(join(root, "integrity/decisions.yaml"), registry);
    context.projectRoot = root;
    const real = await vi.importActual<typeof import("../../core/src/sources/collect-source.js")>("../../core/src/sources/collect-source.js");
    seam.collect.mockImplementation(real.collectSourceBytes);
    const verification = await verifyTrustedEnvelope(envelope, context);
    expect(verification.status).toBe("PASS");
    const barrier = pauseRegistry();
    const pending = releaseVerifiedResponse({ envelope, context, verification });
    await barrier.entered;
    await writeFile(join(root, "docs/source.md"), "changed source");
    barrier.resume();
    const result = await pending;
    expect(result.status).toBe("BLOCKED"); expect(result).not.toHaveProperty("response");
  });
});
