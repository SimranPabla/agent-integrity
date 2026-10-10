import type { AlphaIntegrityReceipt } from "@agent-integrity/protocol";
import type { FileReceiptStore } from "@agent-integrity/core";
import type { ActiveRequestState, ReceiptIssuedState, ReceiptPreparedState, ResultCommittedState } from "./request-state.js";
import type { MutationCapability } from "./state-coordinator.js";
import { RequestStore } from "./request-store.js";
/** Closed durable recovery dispatch. Unknown states fail closed. */
export type DurableRecoveryAction = "RECONCILE_ISSUE" | "INSPECT_CONSUMPTION" | "REPLAY_RESULT" | "RECOVER_RESERVED" | "RECOVER_VERIFIED" | "RECOVER_PASS_CONSUMED" | "REPLAY_RELEASE_REFUSED";
const ACTIONS: Readonly<Record<string, DurableRecoveryAction>> = Object.freeze({
    reserved: "RECOVER_RESERVED", verified: "RECOVER_VERIFIED", "receipt-prepared": "RECONCILE_ISSUE",
    "receipt-issued": "INSPECT_CONSUMPTION", "pass-consumed": "RECOVER_PASS_CONSUMED",
    "release-refused": "REPLAY_RELEASE_REFUSED", "result-committed": "REPLAY_RESULT",
});
export function classifyDurableRecovery(state: string): DurableRecoveryAction {
    if (typeof state !== "string" || !Object.hasOwn(ACTIONS, state))
        throw new Error("unknown or contradictory durable recovery state");
    return ACTIONS[state]!;
}
import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";
import { buildReceipt, createReceipt, canonicalJson, verifyTrustedEnvelope, type TrustedVerificationContext } from "@agent-integrity/core";
import { releaseVerifiedReceipt, type ReleaseResult } from "@agent-integrity/sdk";
import type { EnvelopeVerificationResult } from "@agent-integrity/protocol";
import { openPrivateBundleSnapshot, validateAndSnapshotBundle, type BundleLimits } from "./bundle.js";
import { loadTrustedVerificationContext, closedRecord, freezeTree, type VerificationLimits } from "./trusted-context.js";
import { parseCanonicalServiceRequest, serviceRequestDigest, type ParsedServiceRequest, type ServiceResponse } from "./protocol.js";
import { PrivateObjectStore } from "./private-object-store.js";
import { ReceiptKeyRegistry } from "./key-registry.js";
import type { ReceiptPublicKeyConfig } from "./config.js";
import { recoverConsumedRelease } from "./consumed-release-recovery.js";
import type { VerifyReleaseServiceOptions } from "./service.js";
import { runTrustedVerification } from "./verification-runner.js";
/** Host-owned adapters. No request-selected roots, keys or recovery callbacks. */
export interface DurableServiceAdapters {
    readonly objects: PrivateObjectStore;
    readonly incomingRoot: string;
    readonly snapshotRoot: string;
    readonly bundleLimits: BundleLimits;
    readonly verificationLimits: VerificationLimits;
    readonly maximumRequestBytes: number;
    readonly verificationTimeoutMs: number;
    readonly keyRegistry: () => ReceiptKeyRegistry;
    readonly issuer: string;
}
const sha = (bytes: Uint8Array | string) => createHash("sha256").update(bytes).digest("hex");
const hash = (value: unknown) => sha(canonicalJson(value));
function requireSame(actual: unknown, expected: unknown): void { if (canonicalJson(actual) !== canonicalJson(expected))
    throw new Error("contradictory frozen recovery binding"); }
function originalVerification(state: Exclude<ActiveRequestState, {
    phase: "reserved" | "result-committed";
}>): EnvelopeVerificationResult {
    const verification = { ...state.verification, envelopeDigest: state.envelopeDigest };
    if (hash(verification) !== state.verificationDigest)
        throw new Error("verification digest mismatch");
    return freezeTree(verification);
}
async function originalRequest(adapters: DurableServiceAdapters, options: VerifyReleaseServiceOptions, state: ActiveRequestState): Promise<ParsedServiceRequest> {
    const bytes = await adapters.objects.readCanonicalRequest(state.requestObjectId);
    if (sha(bytes) !== state.requestDigest || state.requestObjectId !== state.requestDigest)
        throw new Error("canonical request digest mismatch");
    const request = parseCanonicalServiceRequest(bytes, adapters.maximumRequestBytes);
    if (serviceRequestDigest(request) !== state.requestDigest || state.clientId !== options.clientId || state.storeGeneration !== options.storeGeneration || request.requestId !== state.requestId || sha(request.idempotencyKey) !== state.idempotencyKeyHash)
        throw new Error("canonical request identity mismatch");
    if (state.phase !== "reserved" && state.phase !== "result-committed" && hash(request.envelope) !== state.envelopeDigest)
        throw new Error("canonical envelope binding mismatch");
    return request;
}
async function originalContext(adapters: DurableServiceAdapters, request: ParsedServiceRequest, snapshotId: string): Promise<TrustedVerificationContext> {
    // Mandatory request binding even though the context loader also validates all files.
    await openPrivateBundleSnapshot({ snapshotRoot: adapters.snapshotRoot, snapshotId, limits: adapters.bundleLimits, expectedRequest: request });
    return loadTrustedVerificationContext({ version: "1", canonicalEnvelope: canonicalJson(request.envelope), snapshotRoot: adapters.snapshotRoot, snapshotId, bundleLimits: adapters.bundleLimits, limits: adapters.verificationLimits });
}
function parsePublicRegistry(bytes: Buffer): readonly ReceiptPublicKeyConfig[] {
    const value: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    if (canonicalJson(value) !== bytes.toString("utf8") || !Array.isArray(value) || value.length < 1 || value.length > 128)
        throw new Error("invalid frozen public registry");
    let previous = "";
    const keys = value.map(entry => {
        const r = closedRecord(entry, ["kid", "x", "notBefore", "notAfter", "revokedAt"]);
        if (typeof r.kid !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(r.kid) || r.kid <= previous || typeof r.x !== "string" || !/^[A-Za-z0-9_-]{43}$/u.test(r.x) || Buffer.from(r.x, "base64url").toString("base64url") !== r.x)
            throw new Error("invalid public key binding");
        for (const t of [r.notBefore, r.notAfter, ...(r.revokedAt === null ? [] : [r.revokedAt])])
            if (typeof t !== "string" || !Number.isFinite(Date.parse(t)) || new Date(t).toISOString() !== t)
                throw new Error("invalid frozen key time");
        if (Date.parse(r.notBefore as string) >= Date.parse(r.notAfter as string) || (r.revokedAt !== null && Date.parse(r.revokedAt as string) < Date.parse(r.notBefore as string)))
            throw new Error("invalid frozen key interval");
        previous = r.kid;
        createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: r.x }, format: "jwk" });
        return r as unknown as ReceiptPublicKeyConfig;
    });
    return freezeTree(keys);
}
async function frozenTrust(adapters: DurableServiceAdapters, state: ReceiptPreparedState | ReceiptIssuedState | Extract<ActiveRequestState, {
    phase: "pass-consumed" | "release-refused";
}>, context: TrustedVerificationContext) {
    const bytes = await adapters.objects.readTrustRegistry(state.trustSnapshotObjectId);
    if (sha(bytes) !== state.trustSnapshotDigest || state.trustSnapshotObjectId !== state.trustSnapshotDigest)
        throw new Error("frozen registry digest mismatch");
    const registry = parsePublicRegistry(bytes), selected = registry.find(k => k.kid === state.keyId);
    if (!selected || hash(selected) !== state.publicKeyDigest || state.signingTime !== state.createdAt || Date.parse(state.signingTime) < Date.parse(selected.notBefore) || Date.parse(state.signingTime) >= Date.parse(selected.notAfter) || selected.revokedAt !== null)
        throw new Error("frozen signing admission mismatch");
    const key = adapters.keyRegistry().privateKey(state.keyId);
    if (!key || createPublicKey(key.privateKey).export({ format: "jwk" }).x !== selected.x)
        throw new Error("original private key is unavailable");
    const keys = Object.fromEntries(registry.map(k => [k.kid, createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: k.x }, format: "jwk" }).export({ type: "spki", format: "pem" }).toString()]));
    const trust = freezeTree({ keys, revokedKeyIds: registry.filter(k => k.revokedAt !== null).map(k => k.kid), issuer: state.issuer, audience: state.audience, purpose: state.purpose, engineVersion: state.engineVersion, trustedPolicy: context.trustedPolicy, maxLifetimeMs: state.maxLifetimeMs });
    const trustAt = (time: Date) => {
        if (!Number.isFinite(time.getTime()))
            throw new Error("invalid fresh release time");
        return freezeTree({ ...trust, keys: Object.fromEntries(registry.filter(k => time.getTime() >= Date.parse(k.notBefore) && time.getTime() < Date.parse(k.notAfter)).map(k => [k.kid, keys[k.kid]!])) });
    };
    return { privateKey: key.privateKey.export({ type: "pkcs8", format: "pem" }).toString(), trust, trustAt };
}
function response(requestId: string, receipt: AlphaIntegrityReceipt, release?: ReleaseResult): ServiceResponse {
    if (release?.status === "PASS") {
        const bytes = Buffer.from(release.response, "utf8");
        return { serviceProtocolVersion: "1", requestId, status: "PASS", verification: receipt.verification as AlphaIntegrityReceipt["verification"] & {
                status: "PASS";
            }, receipt, releasedResponse: { encoding: "base64", bytes: bytes.toString("base64"), sha256: sha(bytes) } };
    }
    if (release)
        return { serviceProtocolVersion: "1", requestId, status: "RELEASE_REFUSED", verification: receipt.verification as AlphaIntegrityReceipt["verification"] & {
                status: "PASS";
            }, receipt, release: { status: release.status, code: "RECEIPT_RECHECK_REFUSED", retryable: false } };
    return { serviceProtocolVersion: "1", requestId, status: receipt.verification.status, verification: receipt.verification, receipt } as ServiceResponse;
}
/** Actual disk-backed phase driver. Every iteration reloads the admitted request and pinned inputs. */
export async function recoverServiceTransaction(options: VerifyReleaseServiceOptions, adapters: DurableServiceAdapters, capability: MutationCapability, initial: ActiveRequestState, now: () => Date, signal?: AbortSignal): Promise<ServiceResponse> {
    // Existing active recovery is also the bounded maintenance admission seam.
    // Completed/tombstone retries bypass this driver entirely and remain lookup-only.
    if (initial.phase !== "result-committed")
        await options.requestStore.resumeExpiredCompactions(capability, now());
    let state = initial;
    // Only this invocation's newly issued receipt may attempt ordinary SDK consumption.
    let freshlyIssued = false;
    let freshlyPrepared = false;
    const store = options.receiptStore(capability);
    for (;;) {
        if (state.phase === "result-committed")
            return state.response;
        const request = await originalRequest(adapters, options, state);
        if (state.phase === "reserved") {
            const snapshot = await validateAndSnapshotBundle({ request, incomingRoot: adapters.incomingRoot, snapshotRoot: adapters.snapshotRoot, nowMs: now().getTime(), limits: adapters.bundleLimits });
            const context = await originalContext(adapters, request, snapshot.snapshotId);
            const checked = await runTrustedVerification({ version: "1", canonicalEnvelope: canonicalJson(request.envelope), snapshotRoot: adapters.snapshotRoot, snapshotId: snapshot.snapshotId, bundleLimits: adapters.bundleLimits, limits: adapters.verificationLimits }, { timeoutMs: adapters.verificationTimeoutMs, ...(signal === undefined ? {} : { signal }) });
            if (checked.kind !== "verified")
                throw new Error("pure verifier failed");
            const verification = checked.verification;
            state = await options.requestStore.advance(capability, state, { phase: "verified", snapshotId: snapshot.snapshotId, envelopeDigest: verification.envelopeDigest, verificationDigest: hash(verification), verification: { protocolVersion: verification.protocolVersion, status: verification.status, findings: verification.findings } });
            continue;
        }
        const context = await originalContext(adapters, request, state.snapshotId);
        const verification = originalVerification(state);
        if (state.phase === "verified") {
            const signingTime = now();
            const registry = adapters.keyRegistry();
            const selected = registry.select(signingTime);
            const publicRegistry = registry.publicSnapshot(), bytes = Buffer.from(canonicalJson(publicRegistry));
            parsePublicRegistry(bytes);
            const trustSnapshotDigest = sha(bytes), trustSnapshotObjectId = await adapters.objects.publishTrustRegistry(bytes, trustSnapshotDigest);
            const metadata = publicRegistry.find(k => k.kid === selected.kid)!;
            if (createPublicKey(selected.privateKey).export({ format: "jwk" }).x !== metadata.x)
                throw new Error("signing private/public key mismatch");
            const run = options.deriveRunAndNonce?.(request) ?? { runId: hash([options.storeGeneration, options.clientId, request.idempotencyKey, state.requestDigest]).slice(0, 32), nonce: hash([state.requestDigest, "receipt-nonce"]).slice(0, 32) };
            const prepared = Buffer.from(request.envelope.response.content, "utf8");
            state = await options.requestStore.advance(capability, state, { phase: "receipt-prepared", issuer: adapters.issuer, signingTime: signingTime.toISOString(), createdAt: signingTime.toISOString(), expiresAt: new Date(signingTime.getTime() + options.maximumReceiptLifetimeMs).toISOString(), trustSnapshotObjectId, trustSnapshotDigest, keyId: selected.kid, publicKeyDigest: hash(metadata), runId: run.runId, receiptNonce: run.nonce, audience: options.audience, purpose: options.purpose, engineVersion: options.engineVersion, maxLifetimeMs: options.maximumReceiptLifetimeMs, receiptOutputName: "receipt-" + hash([options.outputName, state.storeGeneration, state.clientId, state.transactionId, state.requestDigest]) + ".json", receiptOutputRootIdentity: options.outputBoundary.rootIdentityDigest, trustedContextDigest: hash(context), ...(verification.status === "PASS" ? { preparedResponse: { bytes: prepared.toString("base64"), sha256: sha(prepared) } } : {}) });
            freshlyPrepared = true;
            continue;
        }
        await options.outputBoundary.assertIdentity();
        options.outputBoundary.validateName(state.receiptOutputName);
        if (hash(context) !== state.trustedContextDigest || options.outputBoundary.rootIdentityDigest !== state.receiptOutputRootIdentity)
            throw new Error("original snapshot or output boundary changed");
        const frozen = await frozenTrust(adapters, state, context);
        if (state.preparedResponse) {
            const bytes = Buffer.from(state.preparedResponse.bytes, "base64");
            if (bytes.toString("base64") !== state.preparedResponse.bytes || sha(bytes) !== state.preparedResponse.sha256 || !bytes.equals(Buffer.from(request.envelope.response.content, "utf8")))
                throw new Error("original prepared bytes changed");
        }
        if (state.phase === "receipt-prepared") {
            requireSame(await verifyTrustedEnvelope(request.envelope, context), verification);
            const inputs = { runId: state.runId, envelope: request.envelope, verification, createdAt: new Date(state.createdAt), expiresAt: new Date(state.expiresAt), signer: { keyId: state.keyId, privateKey: frozen.privateKey, issuer: state.issuer }, audience: state.audience, purpose: state.purpose, nonce: state.receiptNonce, engineVersion: state.engineVersion, maxLifetimeMs: state.maxLifetimeMs };
            const receipt = freshlyPrepared
                ? await createReceipt({ ...inputs, transactionId: state.transactionId, outputBoundary: options.outputBoundary, outputName: state.receiptOutputName, context, receiptStore: store })
                : buildReceipt(inputs);
            // Recovery always reconciles before inspection; partial records are not absence.
            if (!freshlyPrepared)
                await store.completePreparedIssue(receipt, { transactionId: state.transactionId });
            freshlyPrepared = false;
            const issued = await store.inspectIssuedRecordByDigest(receipt.receiptDigest);
            if (!issued || issued.transactionId !== state.transactionId)
                throw new Error("exact issuance unproven");
            requireSame(issued.receipt, receipt);
            await store.completeReceiptFile(receipt.receiptDigest, options.outputBoundary, state.receiptOutputName);
            state = await options.requestStore.advance(capability, state, { phase: "receipt-issued", receiptDigest: receipt.receiptDigest, receipt });
            freshlyIssued = true;
            continue;
        }
        const issued = await store.inspectIssuedRecordByDigest(state.receiptDigest);
        if (!issued || issued.transactionId !== state.transactionId)
            throw new Error("original issued receipt missing");
        requireSame(issued.receipt, state.receipt);
        // Verify already-issued signatures and every frozen field; never sign again.
        assertFrozenReceipt(state, request, frozen.trust.keys[state.keyId]!);
        await store.completeReceiptFile(state.receiptDigest, options.outputBoundary, state.receiptOutputName);
        const consumed = await store.inspectConsumed(state.receiptDigest), closed = await store.inspectClosed(state.receiptDigest);
        if (consumed && closed)
            throw new Error("consumed and closed markers conflict");
        if (consumed && (consumed.transactionId !== state.transactionId || consumed.runId !== state.runId || consumed.nonce !== state.receiptNonce))
            throw new Error("consumed marker binding mismatch");
        if (closed && closed.transactionId !== state.transactionId)
            throw new Error("closed marker binding mismatch");
        if (state.phase === "release-refused") {
            if (!closed || consumed || hash(closed) !== state.closedMarkerDigest)
                throw new Error("persisted refusal marker mismatch");
            if (!("status" in state.response) || state.response.status !== "RELEASE_REFUSED")
                throw new Error("persisted refusal response missing");
            const originalStatus = state.response.release.status;
            if ((closed.reasonCode === "RELEASE_REVIEW" && originalStatus !== "REVIEW") ||
                (closed.reasonCode === "RELEASE_BLOCKED" && originalStatus !== "BLOCKED") ||
                !["RELEASE_REVIEW", "RELEASE_BLOCKED", "RELEASE_RECHECK_REFUSED"].includes(closed.reasonCode))
                throw new Error("persisted refusal contradicts original close reason");
            // A complete journaled response remains authoritative even for the older
            // generic close reason. Never infer a replacement status or reclose it.
            requireSame(state.response, response(request.requestId, state.receipt, { status: originalStatus, verification }));
            state = await commit(options, capability, state, state.response, now);
            continue;
        }
        if (state.phase === "pass-consumed" || consumed) {
            if (!consumed || closed || !state.preparedResponse)
                throw new Error("consumed release evidence missing");
            if (state.phase === "pass-consumed" && (state.consumedAt !== consumed.consumedAt || state.consumedMarkerDigest !== hash(consumed)))
                throw new Error("persisted consumed marker mismatch");
            const releaseTime = now();
            const release = await recoverConsumedRelease({ receipt: state.receipt, envelope: request.envelope, verification, context, trust: frozen.trustAt(releaseTime), receiptStore: store, expectedTransactionId: state.transactionId, expectedConsumedAt: new Date(consumed.consumedAt), preparedResponseDigest: state.preparedResponse.sha256, preparedResponseBytes: state.preparedResponse.bytes, now: releaseTime });
            if (release.status !== "PASS")
                throw new Error("consumed release fresh validation refused");
            if (state.phase === "receipt-issued") {
                state = await options.requestStore.advance(capability, state, { phase: "pass-consumed", consumedAt: consumed.consumedAt, consumedMarkerDigest: hash(consumed) });
                continue;
            }
            state = await commit(options, capability, state, response(request.requestId, state.receipt, release), now);
            continue;
        }
        if (verification.status !== "PASS") {
            if (closed)
                throw new Error("non-PASS receipt unexpectedly closed");
            state = await commit(options, capability, state, response(request.requestId, state.receipt), now);
            continue;
        }
        let release: ReleaseResult | undefined;
        if (!closed && freshlyIssued) {
            // An SDK exception or non-PASS result never proves consumption did not occur.
            const releaseTime = now();
            try {
                release = await releaseVerifiedReceipt({ envelope: request.envelope, verification, context, receipt: state.receipt, receiptStore: store, now: releaseTime, trust: frozen.trustAt(releaseTime) });
            }
            catch { /* inspect durable records below */ }
            freshlyIssued = false;
            const marker = await store.inspectConsumed(state.receiptDigest);
            if (marker)
                continue;
            if (release?.status === "PASS")
                throw new Error("PASS without consumed evidence");
        }
        // A restarted issued-but-unconsumed PASS is never blindly consumed again.
        const status = closed ? (closed.reasonCode === "RELEASE_REVIEW" ? "REVIEW" : "BLOCKED") : release?.status === "REVIEW" ? "REVIEW" : "BLOCKED";
        if (closed && !['RELEASE_REVIEW', 'RELEASE_BLOCKED'].includes(closed.reasonCode))
            throw new Error("unknown original close reason");
        if (!closed)
            await store.closeIssuedReceipt(state.receiptDigest, { transactionId: state.transactionId, closedAt: now(), reasonCode: status === "REVIEW" ? "RELEASE_REVIEW" : "RELEASE_BLOCKED" });
        const marker = await store.inspectClosed(state.receiptDigest);
        if (!marker || marker.transactionId !== state.transactionId)
            throw new Error("closure evidence missing");
        state = await options.requestStore.advance(capability, state, { phase: "release-refused", closedMarkerDigest: hash(marker), response: response(request.requestId, state.receipt, { status, verification }) });
    }
}
async function commit(options: VerifyReleaseServiceOptions, capability: MutationCapability, state: ActiveRequestState, result: ServiceResponse, now: () => Date): Promise<ActiveRequestState> {
    if (!('receipt' in result) || !('status' in result))
        throw new Error("unsigned result cannot commit");
    const committedAt = now();
    if (!Number.isFinite(committedAt.getTime()) || (result.status === "PASS" && committedAt.getTime() >= Date.parse(result.receipt.expiresAt)))
        throw new Error("fresh result commit time refuses release");
    return options.requestStore.advance(capability, state, { phase: "result-committed", response: result, outcome: result.status, receiptExpiresAt: result.receipt.expiresAt, deliveryDeadline: new Date(Math.min(Date.parse(result.receipt.expiresAt), committedAt.getTime() + options.deliveryWindowMs)).toISOString(), responseBytesRetained: result.status === "PASS" });
}
function assertFrozenReceipt(state: ReceiptIssuedState | Extract<ActiveRequestState, {
    phase: "pass-consumed" | "release-refused";
}>, request: ParsedServiceRequest, publicKey: string): void {
    const { receiptDigest: storedDigest, signature, ...body } = state.receipt;
    if (hash({ ...body, signature }) !== storedDigest || storedDigest !== state.receiptDigest || body.runId !== state.runId || body.nonce !== state.receiptNonce || body.issuer !== state.issuer || body.audience !== state.audience || body.purpose !== state.purpose || body.engineVersion !== state.engineVersion || body.createdAt !== state.createdAt || body.expiresAt !== state.expiresAt || body.envelopeDigest !== state.envelopeDigest || body.policyDigest !== hash(request.envelope.policy) || signature.keyId !== state.keyId || signature.algorithm !== "Ed25519" || Date.parse(state.expiresAt) - Date.parse(state.createdAt) > state.maxLifetimeMs || Date.parse(state.expiresAt) <= Date.parse(state.createdAt))
        throw new Error("issued receipt frozen binding mismatch");
    requireSame(body.verification, state.verification);
    const signatureBytes = Buffer.from(signature.value, "base64");
    if (signatureBytes.length !== 64 || signatureBytes.toString("base64") !== signature.value || !verifySignature(null, Buffer.from(canonicalJson({ protected: { algorithm: signature.algorithm, keyId: signature.keyId }, body })), publicKey, signatureBytes))
        throw new Error("original receipt signature mismatch");
}
