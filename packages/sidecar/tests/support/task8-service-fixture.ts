import { createHash, createHmac, generateKeyPairSync, randomBytes } from "node:crypto";
import { chmod, cp, mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalJson, FileReceiptStore, ReceiptOutputBoundary } from "@agent-integrity/core";
import { PrivateObjectStore } from "../../src/private-object-store.js";
import { RequestStore } from "../../src/request-store.js";
import { StateCoordinator } from "../../src/state-coordinator.js";
import { MutationScheduler } from "../../src/scheduler.js";
import { ReceiptKeyRegistry } from "../../src/key-registry.js";
import { parseCanonicalServiceRequest } from "../../src/protocol.js";
import { VerifyReleaseService, type VerifyReleaseServiceOptions } from "../../src/service.js";
import { FileNonceStore } from "../../src/nonce-store.js";
import { Readiness } from "../../src/readiness.js";
const roots = new Set<string>();
const invocationDrains = new Map<string, () => Promise<void>>();
// Cache only immutable source fixture bytes; each invocation still owns fresh disk roots and generated keys.
let bundleFiles: Promise<readonly { path: string; bytes: Buffer }[]> | undefined;
function fixtureFiles() {
    return bundleFiles ??= (async () => {
        const root = fileURLToPath(new URL("../fixtures/bundle", import.meta.url));
        const files: { path: string; bytes: Buffer }[] = [];
        async function visit(directory: string, prefix: string) {
            for (const entry of await readdir(directory, { withFileTypes: true })) {
                const path = prefix + entry.name;
                if (entry.isDirectory()) await visit(join(directory, entry.name), path + "/");
                else files.push({ path, bytes: await readFile(join(directory, entry.name)) });
            }
        }
        await visit(root, ""); return files;
    })();
}
export async function cleanupServiceFixtures() { for (const root of roots) {
    // Abort pure verification and wait for worker termination, or drain postverified
    // durable completion while its live capability is still held. Never remove beneath a writer.
    await invocationDrains.get(root)?.();
    await rm(root, { recursive: true, force: true });
    invocationDrains.delete(root);
    roots.delete(root);
} }
export const hash = (bytes: string | Uint8Array) => createHash("sha256").update(bytes).digest("hex");
export async function serviceFixture(initialTime = new Date("2030-01-01T00:05:00.000Z"), outcome: "PASS" | "REVIEW" | "BLOCKED" = "PASS", responseContent?: string) {
    const root = await mkdtemp(join(tmpdir(), "task8-real-service-"));
    roots.add(root);
    const pending = new Set<Promise<unknown>>();
    const teardownAbort = new AbortController();
    let retiring = false;
    invocationDrains.set(root, async () => {
        retiring = true; teardownAbort.abort();
        while (pending.size !== 0) await Promise.allSettled([...pending]);
    });
    const trackOperation = <T>(operation: () => Promise<T>): Promise<T> => {
        if (retiring) return Promise.reject(new Error("fixture invocation is retiring"));
        const running = operation(); pending.add(running);
        void running.then(() => pending.delete(running), () => pending.delete(running));
        return running;
    };
    const trackService = (service: VerifyReleaseService) => {
        const process = service.process.bind(service);
        service.process = (body, headers, signal) => {
            if (retiring) return Promise.reject(new Error("fixture invocation is retiring"));
            const operation = process(body, headers, signal === undefined ? teardownAbort.signal : AbortSignal.any([signal, teardownAbort.signal]));
            pending.add(operation);
            void operation.then(() => pending.delete(operation), () => pending.delete(operation));
            return operation;
        };
        return service;
    };
    const stateRoot = join(root, "state"), outputRoot = join(root, "output"), incomingRoot = join(root, "incoming"), snapshotRoot = join(stateRoot, "snapshots");
    for (const path of [stateRoot, outputRoot, incomingRoot, snapshotRoot, join(stateRoot, "transactions")])
        await mkdir(path, { mode: path === incomingRoot ? 0o750 : 0o700 });
    const bundle = join(incomingRoot, "bundle-1");
    await mkdir(bundle, { mode: 0o750 });
    for (const file of await fixtureFiles()) {
        const path = join(bundle, file.path);
        await mkdir(path.slice(0, path.lastIndexOf("/")), { recursive: true, mode: 0o750 });
        await writeFile(path, file.bytes, { mode: 0o640 });
    }
    async function mode(path: string) { await chmod(path, 0o750); for (const entry of await readdir(path, { withFileTypes: true })) {
        const child = join(path, entry.name);
        if (entry.isDirectory())
            await mode(child);
        else
            await chmod(child, 0o640);
    } }
    await mode(bundle);
    const source = await readFile(join(bundle, "project/docs/approved.md"));
    const content = source.toString().trimEnd();
    const policy = { version: 1 as const, sources: { allowedRoots: ["docs"] }, decisions: { path: "integrity/decisions.yaml" }, rules: { requireEvidenceFor: ["factual"], contradictions: "review", rejectedDecisions: "block", responseMutation: "block", replay: "block" } };
    const envelope = { protocolVersion: "1-alpha", policy, response: { content, sections: [{ sectionId: "answer", substantive: true, byteStart: 0, byteEnd: Buffer.byteLength(content), sha256: hash(content) }] }, sources: [{ sourceId: "approved", path: "docs/approved.md", size: source.length, sha256: hash(source) }], decisionRegistryDigest: hash(await readFile(join(bundle, "project/integrity/decisions.yaml"))), decisions: [], evidence: [{ evidenceId: "window", sourceId: "approved", anchor: { byteStart: 0, byteEnd: Buffer.byteLength(content), sha256: hash(content) } }], claims: [{ claimId: "window", sectionId: "answer", kind: "factual", decisionIds: [], evidence: [{ evidenceId: "window", role: "supporting", support: "direct" }] }] };
    if (outcome === "REVIEW")
        envelope.claims[0]!.evidence[0]!.support = "ambiguous";
    if (outcome === "BLOCKED")
        envelope.claims[0]!.evidence = [];
    if (responseContent !== undefined) {
        envelope.response.content = responseContent;
        envelope.response.sections[0]!.byteEnd = Buffer.byteLength(responseContent);
        envelope.response.sections[0]!.sha256 = hash(responseContent);
    }
    const requestBytes = Buffer.from(canonicalJson({ serviceProtocolVersion: "1", requestId: "req-1", idempotencyKey: "idem-1", bundleId: "bundle-1", envelope }));
    const request = parseCanonicalServiceRequest(requestBytes, 1048576);
    const configPath = join(bundle, "project/integrity/trusted-config.json");
    const configBytes = Buffer.from(canonicalJson({ allowedRoots: ["docs"], decisionRegistryPath: "integrity/decisions.yaml", maxSourceBytes: 1048576, maxTotalSourceBytes: 4194304 }));
    await writeFile(configPath, configBytes);
    const manifest = JSON.parse(await readFile(join(bundle, "manifest.json"), "utf8"));
    const configRecord = manifest.files.find((f: {
        path: string;
    }) => f.path === "integrity/trusted-config.json");
    configRecord.bytes = configBytes.length;
    configRecord.sha256 = hash(configBytes);
    manifest.publishedAt = new Date(initialTime.getTime() - 300000).toISOString();
    manifest.expiresAt = new Date(initialTime.getTime() + 300000).toISOString();
    manifest.evidenceCompleteness.collectedAt = manifest.publishedAt;
    manifest.envelopeDigest = hash(canonicalJson(request.envelope));
    delete manifest.manifestDigest;
    manifest.manifestDigest = hash(canonicalJson(manifest));
    await writeFile(join(bundle, "manifest.json"), canonicalJson(manifest));
    let coordinator = await StateCoordinator.acquire(stateRoot, { storeGeneration: "generation-1", nestedLockNames: ["receipts"], nestedLockPaths: { receipts: "receipts/.store-lock.json" } });
    let scheduler = new MutationScheduler(coordinator, { maximumQueued: 1, queueTimeoutMs: 1000 });
    let objects = new PrivateObjectStore(join(stateRoot, "transactions", "private-objects"));
    let requests = new RequestStore(join(stateRoot, "requests"), objects);
    const pair = generateKeyPairSync("ed25519");
    const publicJwk = pair.publicKey.export({ format: "jwk" });
    let registry = new ReceiptKeyRegistry("key1", [{ kid: "key1", x: publicJwk.x!, notBefore: "2025-01-01T00:00:00.000Z", notAfter: "2031-01-01T00:00:00.000Z", revokedAt: null, publicKey: pair.publicKey }], [{ kid: "key1", privateKey: pair.privateKey }]);
    let time = new Date(initialTime), fault: ((point: string) => void | Promise<void>) | undefined;
    const authSecret = randomBytes(32), authRegistry = { clients: { "client-1": { keys: { auth1: { secret: authSecret, validFromMs: initialTime.getTime() - 60000, validUntilMs: initialTime.getTime() + 7 * 24 * 3600000 } } } } };
    let readiness = new Readiness(["CONFIGURATION"]); readiness.set("CONFIGURATION", true);
    const nonceStore = new FileNonceStore(join(stateRoot, "nonces"), { maximumSkewMs: 60000 });
const options: VerifyReleaseServiceOptions = { requestStore: requests, scheduler, receiptStore: (capability: Parameters<StateCoordinator["receiptStoreLockOwnership"]>[0]) => new FileReceiptStore(join(stateRoot, "receipts"), { lockOwnership: coordinator.receiptStoreLockOwnership(capability), faultInjector: point => fault?.(point) }), clientId: "client-1", authRegistry, nonceStore, readiness, outputBoundary: await ReceiptOutputBoundary.open(outputRoot), outputName: "receipt.json", storeGeneration: "generation-1", audience: "audience", purpose: "sidecar", engineVersion: "engine", maximumReceiptLifetimeMs: 60000, deliveryWindowMs: 120000, now: () => new Date(time), transactionId: () => "transaction-1", deriveRunAndNonce: () => ({ runId: "run-1", nonce: "nonce-1" }), durable: { objects, incomingRoot, snapshotRoot, keyRegistry: () => registry, issuer: "issuer", maximumRequestBytes: 1048576, verificationTimeoutMs: 5000, bundleLimits: { maxManifestBytes: 1048576, maxAllowedSourceRoots: 64, maxFiles: 10000, maxPathBytes: 1024, maxFileBytes: 1048576, maxTotalBytes: 4194304, maxFutureSkewMs: 60000, maxBundleLifetimeMs: 900000 }, verificationLimits: { maxInputBytes: 1048576, maxOutputBytes: 1048576, maxPolicyBytes: 1048576, maxConfigBytes: 1048576, maxSourceBytes: 1048576, maxTotalSourceBytes: 4194304, maxItems: 10000, maxFindings: 10000, maxFindingBytes: 65536 } } };
    const authHeaders = (body = requestBytes) => { const timestampMs = String(time.getTime()), nonce = randomBytes(16).toString("hex"), fields = ["POST", "/v1/verify-release", request.serviceProtocolVersion, "client-1", "auth1", timestampMs, nonce, hash(body)], encode = Buffer.concat([Buffer.from("agent-integrity-sidecar-auth-v1"), ...fields.map(field => { const b = Buffer.from(field); const n = Buffer.alloc(4); n.writeUInt32BE(b.length); return Buffer.concat([n, b]); })]); return { clientId: "client-1", keyId: "auth1", timestampMs, nonce, mac: createHmac("sha256", authSecret).update(encode).digest("base64url") }; };
    const authHeadersFor = (clientId: string, keyId: string, secret: Uint8Array, body = requestBytes, nonceOverride?: string) => { const timestampMs = String(time.getTime()), nonce = nonceOverride ?? randomBytes(16).toString("hex"), fields = ["POST", "/v1/verify-release", request.serviceProtocolVersion, clientId, keyId, timestampMs, nonce, hash(body)], encode = Buffer.concat([Buffer.from("agent-integrity-sidecar-auth-v1"), ...fields.map(field => { const b = Buffer.from(field); const n = Buffer.alloc(4); n.writeUInt32BE(b.length); return Buffer.concat([n, b]); })]); return { clientId, keyId, timestampMs, nonce, mac: createHmac("sha256", secret).update(encode).digest("base64url") }; };
    return { trackOperation, trackService, root, stateRoot, outputRoot, incomingRoot, snapshotRoot, get objects() { return objects; }, get requests() { return requests; }, request, requestBytes, authHeaders, authHeadersFor, authSecret, get coordinator() { return coordinator; }, options, newService: () => trackService(new VerifyReleaseService({ ...options, scheduler, requestStore: requests, durable: { ...options.durable!, objects } })), restart: async () => { await coordinator.close(); coordinator = await StateCoordinator.acquire(stateRoot, { storeGeneration: "generation-1", nestedLockNames: ["receipts"], nestedLockPaths: { receipts: "receipts/.store-lock.json" } }); scheduler = new MutationScheduler(coordinator, { maximumQueued: 1, queueTimeoutMs: 1000 }); objects = new PrivateObjectStore(join(stateRoot, "transactions", "private-objects")); requests = new RequestStore(join(stateRoot, "requests"), objects); readiness = new Readiness(["CONFIGURATION"]); readiness.set("CONFIGURATION", true); options.readiness = readiness; }, setTime: (value: Date) => { time = value; }, setFault: (value: typeof fault) => { fault = value; }, setRegistry: (value: ReceiptKeyRegistry) => { registry = value; }, registry: () => registry, store: () => new FileReceiptStore(join(stateRoot, "receipts")) };
}
