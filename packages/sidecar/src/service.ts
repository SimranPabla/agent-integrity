import { createHash, randomUUID } from "node:crypto";
import { type createReceipt, type FileReceiptStore, type TrustedVerificationContext } from "@agent-integrity/core";
import type { AlphaIntegrityReceipt, EnvelopeVerificationResult } from "@agent-integrity/protocol";
import { type releaseVerifiedReceipt } from "@agent-integrity/sdk";
import { MutationScheduler, AdmissionError } from "./scheduler.js";
import { RequestStore } from "./request-store.js";
import type { MutationCapability } from "./state-coordinator.js";
import { serviceRequestDigest, type ParsedServiceRequest, type ServiceResponse } from "./protocol.js";
import { parseCanonicalServiceRequest } from "./protocol.js";
import { authenticateRequest, type AuthHeaders, type HmacRegistry } from "./auth.js";
import type { FileNonceStore, NonceRecord } from "./nonce-store.js";
import { Readiness } from "./readiness.js";
import { recoverServiceTransaction, type DurableServiceAdapters } from "./recovery.js";
export class ServiceUnavailableError extends Error {
    readonly code = "SERVICE_UNAVAILABLE" as const;
    readonly retryable = true as const;
    constructor(readonly reason: string) { super(reason); this.name = "ServiceUnavailableError"; }
}
export function exactResponseBytes(status: string, response: string): Buffer {
    if (status !== "PASS")
        throw new ServiceUnavailableError("RELEASE_NOT_PERMITTED");
    if (typeof response !== "string")
        throw new TypeError("released response must be a string");
    return Buffer.from(response, "utf8");
}
export interface ReleasedResponseMetadata {
    readonly encoding: "base64";
    readonly sha256: string;
    readonly bytes: string;
}
export function releasedResponseMetadata(bytes: Uint8Array): ReleasedResponseMetadata {
    const value = Buffer.from(bytes);
    return Object.freeze({ encoding: "base64", sha256: createHash("sha256").update(value).digest("hex"), bytes: value.toString("base64") });
}
export interface ServiceVerification {
    readonly verification: EnvelopeVerificationResult;
    readonly context: TrustedVerificationContext;
    readonly trust: Parameters<typeof releaseVerifiedReceipt>[0]["trust"];
}
export interface ServiceSigner {
    readonly keyId: string;
    readonly privateKey: string;
    readonly issuer: string;
    readonly publicKeyDigest: string;
}
export interface ServiceSnapshot {
    readonly snapshotId: string;
    readonly trustedContextDigest: string;
    readonly trustSnapshotObjectId: string;
    readonly trustSnapshotDigest: string;
}
export interface VerifyReleaseServiceOptions {
    readonly requestStore: RequestStore;
    readonly scheduler: MutationScheduler;
    readonly receiptStore: (capability: MutationCapability) => FileReceiptStore;
    readonly clientId: string;
    readonly durable: DurableServiceAdapters;
    readonly onRecoveryFailure?: (reason: "RECOVERY_REQUIRED") => void;
    readonly outputBoundary: Parameters<typeof createReceipt>[0]["outputBoundary"];
    readonly outputName: string;
    readonly storeGeneration: string;
    readonly audience: string;
    readonly purpose: string;
    readonly engineVersion: string;
    readonly maximumReceiptLifetimeMs: number;
    readonly deliveryWindowMs: number;
    readonly now?: () => Date;
    readonly transactionId?: () => string;
    readonly deriveRunAndNonce?: (request: ParsedServiceRequest) => Readonly<{
        runId: string;
        nonce: string;
    }>;
    readonly authRegistry: HmacRegistry;
    readonly nonceStore: Pick<FileNonceStore, "consume">;
    readonly readiness: Readiness;
    readonly maximumAuthSkewMs?: number;
    readonly authMethod?: string;
    readonly authPath?: string;
}
function captureHeaders(input: AuthHeaders): AuthHeaders {
    if (input === null || typeof input !== "object" || Array.isArray(input) || Object.getPrototypeOf(input) !== Object.prototype) throw new Error("AUTHENTICATION_FAILED");
    const descriptors = Object.getOwnPropertyDescriptors(input);
    const expected = ["clientId", "keyId", "mac", "nonce", "timestampMs"];
    const keys = Reflect.ownKeys(descriptors);
    if (keys.some(key => typeof key !== "string") || keys.length !== expected.length || expected.some(key => !Object.prototype.hasOwnProperty.call(descriptors, key))) throw new Error("AUTHENTICATION_FAILED");
    if (Object.values(descriptors).some(descriptor => descriptor.get !== undefined || descriptor.set !== undefined || descriptor.enumerable !== true || !("value" in descriptor) || typeof descriptor.value !== "string")) throw new Error("AUTHENTICATION_FAILED");
    return Object.freeze(Object.fromEntries(expected.map(key => [key, descriptors[key]!.value])) as AuthHeaders);
}
function captureRegistry(input: HmacRegistry): HmacRegistry {
    if (input === null || typeof input !== "object" || Array.isArray(input) || Object.getPrototypeOf(input) !== Object.prototype) throw new Error("HMAC registry is invalid");
    const root = Object.getOwnPropertyDescriptors(input);
    const clientsDescriptor = root.clients;
    if (!clientsDescriptor || clientsDescriptor.get !== undefined || clientsDescriptor.set !== undefined || !("value" in clientsDescriptor)) throw new Error("HMAC registry is invalid");
    const clients: Record<string, { keys: Record<string, { secret: Uint8Array; validFromMs: number; validUntilMs: number; revokedAtMs?: number }> }> = {};
    for (const [clientId, clientDescriptor] of Object.entries(Object.getOwnPropertyDescriptors(clientsDescriptor.value))) {
        if (clientDescriptor.get !== undefined || clientDescriptor.set !== undefined || !("value" in clientDescriptor)) throw new Error("HMAC registry is invalid");
        const keysDescriptor = Object.getOwnPropertyDescriptors(clientDescriptor.value).keys;
        if (!keysDescriptor || keysDescriptor.get !== undefined || keysDescriptor.set !== undefined || !("value" in keysDescriptor)) throw new Error("HMAC registry is invalid");
        const keys: Record<string, { secret: Uint8Array; validFromMs: number; validUntilMs: number; revokedAtMs?: number }> = {};
        for (const [keyId, keyDescriptor] of Object.entries(Object.getOwnPropertyDescriptors(keysDescriptor.value))) {
            if (keyDescriptor.get !== undefined || keyDescriptor.set !== undefined || !("value" in keyDescriptor)) throw new Error("HMAC registry is invalid");
            const key = keyDescriptor.value as { secret: Uint8Array; validFromMs: number; validUntilMs: number; revokedAtMs?: number };
            keys[keyId] = Object.freeze({ secret: Uint8Array.from(key.secret), validFromMs: key.validFromMs, validUntilMs: key.validUntilMs, ...(key.revokedAtMs === undefined ? {} : { revokedAtMs: key.revokedAtMs }) });
        }
        clients[clientId] = Object.freeze({ keys: Object.freeze(keys) });
    }
    return Object.freeze({ clients: Object.freeze(clients) });
}
/** Durable verify/sign/consume/release orchestration. Every mutation runs under scheduler ownership. */
export class VerifyReleaseService {
    readonly #options: VerifyReleaseServiceOptions;
    #recoveryFailure: "RECOVERY_REQUIRED" | undefined;
    get recoveryFailure(): "RECOVERY_REQUIRED" | undefined { return this.#recoveryFailure; }
    constructor(options: VerifyReleaseServiceOptions) {
        if (!Number.isSafeInteger(options.maximumReceiptLifetimeMs) || options.maximumReceiptLifetimeMs < 1)
            throw new TypeError("maximum receipt lifetime is invalid");
        if (!Number.isSafeInteger(options.deliveryWindowMs) || options.deliveryWindowMs < 1)
            throw new TypeError("delivery window is invalid");
        if (!options.durable)
            throw new TypeError("concrete durable recovery adapters are required");
        if (!options.authRegistry || !options.nonceStore || !options.readiness)
            throw new TypeError("authentication and readiness dependencies are required");
        const maximumAuthSkewMs = options.maximumAuthSkewMs ?? 60_000;
        if (!Number.isSafeInteger(maximumAuthSkewMs) || maximumAuthSkewMs < 0 || maximumAuthSkewMs > 60_000) throw new TypeError("authentication skew is invalid");
        const registry = captureRegistry(options.authRegistry);
        this.#options = Object.freeze({ ...options, authRegistry: registry, maximumAuthSkewMs, durable: Object.freeze({ ...options.durable, bundleLimits: Object.freeze({ ...options.durable.bundleLimits }), verificationLimits: Object.freeze({ ...options.durable.verificationLimits }) }) });
    }
    /** Transport-neutral public boundary: parse and authenticate the exact raw body before queueing. */
    async process(rawRequestBytes: Uint8Array, headers: AuthHeaders, signal?: AbortSignal): Promise<ServiceResponse> {
        if (!(rawRequestBytes instanceof Uint8Array) || rawRequestBytes.byteLength > this.#options.durable.maximumRequestBytes) { const error = new Error("AUTHENTICATION_FAILED"); Object.assign(error, { code: "AUTHENTICATION_FAILED" }); throw error; }
        const admittedBytes = Buffer.from(rawRequestBytes);
        let request: ParsedServiceRequest;
        let authenticated: ReturnType<typeof authenticateRequest>;
        let capturedHeaders: AuthHeaders;
        try {
            request = parseCanonicalServiceRequest(admittedBytes, this.#options.durable.maximumRequestBytes);
            capturedHeaders = captureHeaders(headers);
            const nowMs = (this.#options.now?.() ?? new Date()).getTime();
            if (!Number.isSafeInteger(nowMs)) throw new Error("invalid current time");
            authenticated = authenticateRequest({ request, method: this.#options.authMethod ?? "POST", path: this.#options.authPath ?? "/v1/verify-release", headers: capturedHeaders, nowMs, maximumSkewMs: this.#options.maximumAuthSkewMs!, registry: this.#options.authRegistry });
            if (authenticated.clientId !== this.#options.clientId) throw new Error("client identity mismatch");
        } catch {
            const error = new Error("AUTHENTICATION_FAILED"); Object.assign(error, { code: "AUTHENTICATION_FAILED" }); throw error;
        }
        if (!this.#options.readiness.snapshot().ready) throw new ServiceUnavailableError("NOT_READY");
        return this.#options.scheduler.run(async (capability) => {
            try {
                // A preceding transaction can latch recovery failure while this request waits.
                // Recheck under the acquired capability, before any authentication nonce write.
                if (!this.#options.readiness.snapshot().ready) throw new ServiceUnavailableError("NOT_READY");
                const admissionNowMs = (this.#options.now?.() ?? new Date()).getTime();
                if (!Number.isSafeInteger(admissionNowMs)) { const error = new Error("AUTHENTICATION_FAILED"); Object.assign(error, { code: "AUTHENTICATION_FAILED" }); throw error; }
                try {
                    authenticateRequest({ request, method: this.#options.authMethod ?? "POST", path: this.#options.authPath ?? "/v1/verify-release", headers: capturedHeaders, nowMs: admissionNowMs, maximumSkewMs: this.#options.maximumAuthSkewMs!, registry: this.#options.authRegistry });
                } catch {
                    const error = new Error("AUTHENTICATION_FAILED"); Object.assign(error, { code: "AUTHENTICATION_FAILED" }); throw error;
                }
                try {
                    await this.#options.nonceStore.consume({ version: 1, clientId: authenticated.clientId, keyId: authenticated.keyId, nonce: authenticated.nonce, timestampMs: authenticated.timestampMs, bodyDigest: authenticated.bodyDigest, retainedUntilMs: authenticated.timestampMs + (this.#options.maximumAuthSkewMs ?? 60_000) + 1 } satisfies NonceRecord);
                } catch (cause) {
                    if (cause instanceof Error && /replay/u.test(cause.message)) { const error = new Error("REPLAY_DETECTED"); Object.assign(error, { code: "REPLAY_DETECTED" }); throw error; }
                    throw cause;
                }
                return await this.#process(capability, request, signal, admittedBytes);
            }
            catch (error) {
                if (!(error instanceof ServiceUnavailableError) && !(error instanceof Error && (error.message === "idempotency-key digest conflict" || error.message === "AUTHENTICATION_FAILED" || error.message === "REPLAY_DETECTED")))
                    this.#failRecovery();
                throw error;
            }
        }, signal).catch((error: unknown) => {
            // Coordinator acquisition can fail before the callback executes. Admission
            // errors are non-mutating; unknown root-authority failures latch readiness.
            if (error instanceof ServiceUnavailableError ||
                (error instanceof Error && (error instanceof AdmissionError || error.message === "AUTHENTICATION_FAILED" || error.message === "REPLAY_DETECTED" || error.message === "idempotency-key digest conflict"))) throw error;
            return this.#failRecovery();
        });
    }
    async #process(capability: MutationCapability, request: ParsedServiceRequest, signal?: AbortSignal, admittedBytes?: Buffer): Promise<ServiceResponse> {
        const now = this.#options.now ?? (() => new Date());
        const requestDigest = serviceRequestDigest(request);
        let state = await this.#options.requestStore.lookup(this.#options.clientId, this.#options.storeGeneration, request.idempotencyKey, requestDigest);
        if (state?.phase === "tombstone")
            throw new ServiceUnavailableError("RESULT_EXPIRED");
        if (state?.phase === "result-committed") {
            const currentTime = now();
            if (!Number.isFinite(currentTime.getTime()))
                throw new ServiceUnavailableError("INVALID_CURRENT_TIME");
            const deadline = new Date(state.deliveryDeadline).getTime();
            const receiptExpiry = new Date(state.receiptExpiresAt).getTime();
            if (currentTime.getTime() >= Math.min(deadline, receiptExpiry)) {
                if (currentTime.getTime() >= deadline)
                    await this.#options.requestStore.compactExpired(capability, state, currentTime);
                throw new ServiceUnavailableError("RESULT_EXPIRED");
            }
            return state.response;
        }
        if (state === undefined) {
            if (admittedBytes === undefined || createHash("sha256").update(admittedBytes).digest("hex") !== requestDigest)
                throw new ServiceUnavailableError("ADMITTED_REQUEST_BYTES_REQUIRED");
            state = await this.#options.requestStore.reserve(capability, { clientId: this.#options.clientId, storeGeneration: this.#options.storeGeneration, idempotencyKey: request.idempotencyKey, requestDigest, requestId: request.requestId, transactionId: this.#options.transactionId?.() ?? randomUUID(), canonicalRequest: admittedBytes });
        }
        return recoverServiceTransaction(this.#options, this.#options.durable, capability, state, now, signal);
    }
    #failRecovery(): never {
        this.#recoveryFailure = "RECOVERY_REQUIRED";
        this.#options.readiness.fail("RECOVERY_REQUIRED");
        try {
            this.#options.onRecoveryFailure?.("RECOVERY_REQUIRED");
        }
        catch { /* readiness callbacks must not expose internal errors */ }
        throw new ServiceUnavailableError("RECOVERY_REQUIRED");
    }
}
