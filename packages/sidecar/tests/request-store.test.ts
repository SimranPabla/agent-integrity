import { createHash, generateKeyPairSync } from "node:crypto";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";
import { buildReceipt, FileReceiptStore } from "@agent-integrity/core";
import {
  PrivateObjectStore,
  RequestStore,
  StateCoordinator,
  parseRequestState,
  requestStateDigest,
} from "../src/index.js";

const sha = (bytes: Uint8Array | string) => createHash("sha256").update(bytes).digest("hex");
const execFileAsync = promisify(execFile);
const canonicalRequest = Buffer.from('{"bundleId":"bundle-1","idempotencyKey":"idem-1","requestId":"request-1","serviceProtocolVersion":"1"}', "utf8");
const signingPair = generateKeyPairSync("ed25519");
function receipt(status: "PASS" | "REVIEW") {
  return buildReceipt({
    runId: `run-${status.toLowerCase()}`,
    envelope: { policy: {} } as never,
    verification: { protocolVersion: "1-alpha", status, findings: [], envelopeDigest: sha("envelope") },
    createdAt: new Date("2026-09-29T16:00:00.000Z"), expiresAt: new Date("2026-09-29T17:00:00.000Z"),
    signer: { keyId: "key-1", issuer: "issuer-1", privateKey: signingPair.privateKey.export({ type: "pkcs8", format: "pem" }).toString() },
    audience: "cage", purpose: "response-release", nonce: `nonce-${status.toLowerCase()}`, engineVersion: "0.1.0-alpha.2",
  });
}
function preparedFields(status: "PASS" | "REVIEW") {
  return {
    phase: "receipt-prepared" as const, signingTime: "2026-09-29T16:00:00.000Z", trustSnapshotObjectId: sha("trust"),
    trustSnapshotDigest: sha("trust"), keyId: "key-1", publicKeyDigest: sha("public-key"), runId: `run-${status.toLowerCase()}`,
    receiptNonce: `nonce-${status.toLowerCase()}`, createdAt: "2026-09-29T16:00:00.000Z", expiresAt: "2026-09-29T17:00:00.000Z",
    audience: "cage", purpose: "response-release", engineVersion: "0.1.0-alpha.2", maxLifetimeMs: 3_600_000,
    receiptOutputName: "receipt.json", receiptOutputRootIdentity: sha("output-root"), trustedContextDigest: sha("context"),
  };
}

async function harness(generation = "generation-1") {
  const root = await mkdtemp(join(tmpdir(), "sidecar-request-store-"));
  const coordinator = await StateCoordinator.acquire(join(root, "state"), {
    storeGeneration: generation,
    nestedLockNames: ["receipt-store"],
  });
  const objects = new PrivateObjectStore(join(root, "objects"));
  const requests = new RequestStore(join(root, "requests"), objects, { maxRecords: 8 });
  return { root, coordinator, objects, requests };
}

function reservationInput(generation = "generation-1") {
  return {
    clientId: "cage",
    storeGeneration: generation,
    idempotencyKey: "idem-1",
    requestDigest: sha(canonicalRequest),
    requestId: "request-1",
    transactionId: "transaction-1",
    canonicalRequest,
  };
}

describe("closed request-state graph", () => {
  it("rejects unknown fields and produces stable state digests", () => {
    const state = {
      version: 1,
      phase: "reserved",
      clientId: "cage",
      storeGeneration: "generation-1",
      idempotencyKeyHash: sha("idem-1"),
      requestDigest: sha(canonicalRequest),
      requestId: "request-1",
      transactionId: "transaction-1",
      requestObjectId: sha(canonicalRequest),
    } as const;
    expect(parseRequestState(state)).toEqual(state);
    expect(requestStateDigest(parseRequestState(state))).toMatch(/^[a-f0-9]{64}$/u);
    expect(() => parseRequestState({ ...state, unknown: true })).toThrow(/unknown|exact|invalid/u);
  });

  it("permits only the approved branch-specific transitions", async () => {
    const { coordinator, requests } = await harness();
    await coordinator.withMutation(async (capability) => {
      const reserved = await requests.reserve(capability, reservationInput());
      const verified = await requests.advance(capability, reserved, {
        phase: "verified",
        snapshotId: sha("snapshot"),
        envelopeDigest: sha("envelope"),
        verificationDigest: sha("verification"),
        verification: { protocolVersion: "1-alpha", status: "PASS", findings: [] },
      });
      await expect(requests.advance(capability, verified, {
        phase: "result-committed",
        response: { serviceProtocolVersion: "1", requestId: "request-1", error: { code: "INTERNAL_FAILURE", retryable: false } },
        outcome: "BLOCKED",
        receiptExpiresAt: "2026-09-29T18:00:00.000Z",
        deliveryDeadline: "2026-09-29T17:00:00.000Z",
        responseBytesRetained: false,
      })).rejects.toThrow(/transition/u);
    });
    await coordinator.close();
  });

  it("persists both approved terminal branches with closed signed responses", async () => {
    const passHarness = await harness();
    await passHarness.coordinator.withMutation(async (capability) => {
      const reserved = await passHarness.requests.reserve(capability, reservationInput());
      const verification = { protocolVersion: "1-alpha" as const, status: "PASS" as const, findings: [] };
      const verified = await passHarness.requests.advance(capability, reserved, { phase: "verified", snapshotId: sha("snapshot"), envelopeDigest: sha("envelope"), verificationDigest: sha("verification"), verification });
      const prepared = await passHarness.requests.advance(capability, verified, preparedFields("PASS"));
      const signed = receipt("PASS");
      const issued = await passHarness.requests.advance(capability, prepared, { phase: "receipt-issued", receiptDigest: signed.receiptDigest, receipt: signed });
      const consumed = await passHarness.requests.advance(capability, issued, { phase: "pass-consumed", consumedMarkerDigest: sha("consumed"), consumedAt: "2026-09-29T16:05:00.000Z" });
      const bytes = Buffer.from("released", "utf8");
      await expect(passHarness.requests.advance(capability, consumed, {
        phase: "result-committed", outcome: "PASS", receiptExpiresAt: signed.expiresAt, deliveryDeadline: "2026-09-29T16:30:00.000Z", responseBytesRetained: true,
        response: { serviceProtocolVersion: "1", requestId: "request-1", status: "PASS", verification, receipt: signed, releasedResponse: { encoding: "base64", sha256: sha(bytes), bytes: bytes.toString("base64") } },
      })).resolves.toMatchObject({ phase: "result-committed", outcome: "PASS" });
    });
    await passHarness.coordinator.close();

    const reviewHarness = await harness();
    await reviewHarness.coordinator.withMutation(async (capability) => {
      const reserved = await reviewHarness.requests.reserve(capability, reservationInput());
      const verification = { protocolVersion: "1-alpha" as const, status: "REVIEW" as const, findings: [] };
      const verified = await reviewHarness.requests.advance(capability, reserved, { phase: "verified", snapshotId: sha("snapshot"), envelopeDigest: sha("envelope"), verificationDigest: sha("verification"), verification });
      const prepared = await reviewHarness.requests.advance(capability, verified, preparedFields("REVIEW"));
      const signed = receipt("REVIEW");
      const issued = await reviewHarness.requests.advance(capability, prepared, { phase: "receipt-issued", receiptDigest: signed.receiptDigest, receipt: signed });
      await expect(reviewHarness.requests.advance(capability, issued, {
        phase: "result-committed", outcome: "REVIEW", receiptExpiresAt: signed.expiresAt, deliveryDeadline: "2026-09-29T16:30:00.000Z", responseBytesRetained: true,
        response: { serviceProtocolVersion: "1", requestId: "request-1", status: "REVIEW", verification, receipt: signed },
      })).resolves.toMatchObject({ phase: "result-committed", outcome: "REVIEW" });
    });
    await reviewHarness.coordinator.close();
  });
});

describe("idempotency and private request objects", () => {
  it("publishes exact request bytes before reservation and returns exact retries", async () => {
    const { coordinator, objects, requests } = await harness();
    await coordinator.withMutation(async (capability) => {
      const first = await requests.reserve(capability, reservationInput());
      expect(await objects.readCanonicalRequest(first.requestObjectId)).toEqual(canonicalRequest);
      expect(first.requestDigest).toBe(sha(canonicalRequest));
      expect((await requests.reserve(capability, reservationInput())).transactionId).toBe(first.transactionId);
      await expect(requests.reserve(capability, { ...reservationInput(), requestDigest: sha("changed"), canonicalRequest: Buffer.from("changed") })).rejects.toThrow(/conflict|digest/u);
    });
    await coordinator.close();
  });

  it("keeps a permanent digest binding after result expiry and compaction", async () => {
    const { coordinator, requests } = await harness();
    await coordinator.withMutation(async (capability) => {
      const reserved = await requests.reserve(capability, reservationInput());
      const terminal = await requests.advance(capability, reserved, {
        phase: "result-committed",
        response: { serviceProtocolVersion: "1", requestId: "request-1", error: { code: "INTERNAL_FAILURE", retryable: false } },
        outcome: "BLOCKED",
        receiptExpiresAt: "2026-09-29T18:00:00.000Z",
        deliveryDeadline: "2026-09-29T17:00:00.000Z",
        responseBytesRetained: false,
      }, { allowTechnicalTerminal: true });
      await requests.compactExpired(capability, terminal, new Date("2026-09-29T17:00:00.000Z"));
      const lookup = await requests.lookup("cage", "generation-1", "idem-1", sha(canonicalRequest));
      expect(lookup?.phase).toBe("tombstone");
      await expect(requests.reserve(capability, reservationInput())).rejects.toThrow(/expired|tombstone|reused/u);
      await expect(requests.reserve(capability, { ...reservationInput(), requestDigest: sha("changed"), canonicalRequest: Buffer.from("changed") })).rejects.toThrow(/conflict|digest/u);
    });
    await coordinator.close();
  });

  it("scopes idempotency explicitly to store generation", async () => {
    const first = await harness("generation-1");
    await first.coordinator.withMutation((capability) => first.requests.reserve(capability, reservationInput("generation-1")));
    await first.coordinator.close();
    const second = await harness("generation-2");
    await expect(second.coordinator.withMutation((capability) => second.requests.reserve(capability, reservationInput("generation-2")))).resolves.toMatchObject({ storeGeneration: "generation-2" });
    await second.coordinator.close();
  });

  it("fails closed at capacity and before publishing a binding on object-sync failure", async () => {
    const root = await mkdtemp(join(tmpdir(), "sidecar-request-limits-"));
    const coordinator = await StateCoordinator.acquire(join(root, "state"), { storeGeneration: "generation-1", nestedLockNames: ["receipt-store"] });
    const objects = new PrivateObjectStore(join(root, "objects"));
    const requests = new RequestStore(join(root, "requests"), objects, { maxRecords: 1 });
    await coordinator.withMutation(async (capability) => {
      await requests.reserve(capability, reservationInput());
      const nextBytes = Buffer.from('{"requestId":"request-2"}', "utf8");
      await expect(requests.reserve(capability, { ...reservationInput(), idempotencyKey: "idem-2", requestId: "request-2", transactionId: "transaction-2", requestDigest: sha(nextBytes), canonicalRequest: nextBytes })).rejects.toThrow(/capacity/u);
    });
    await coordinator.close();

    const faultRoot = await mkdtemp(join(tmpdir(), "sidecar-request-fault-"));
    const faultCoordinator = await StateCoordinator.acquire(join(faultRoot, "state"), { storeGeneration: "generation-1", nestedLockNames: ["receipt-store"] });
    const faultObjects = new PrivateObjectStore(join(faultRoot, "objects"), { faultInjector: (point) => { if (point === "file:before-sync") throw new Error("injected object sync failure"); } });
    const faultRequests = new RequestStore(join(faultRoot, "requests"), faultObjects);
    await expect(faultCoordinator.withMutation((capability) => faultRequests.reserve(capability, reservationInput()))).rejects.toThrow(/injected object sync failure/u);
    expect(await readdir(join(faultRoot, "requests", "bindings"))).toEqual([]);
    await faultCoordinator.close();
  });
});

describe("state-root ownership", () => {
  it("rejects a second process owner and never steals the existing lease", async () => {
    const root = await mkdtemp(join(tmpdir(), "sidecar-coordinator-"));
    const path = join(root, "state");
    const first = await StateCoordinator.acquire(path, { storeGeneration: "generation-1", nestedLockNames: ["receipt-store"] });
    await expect(StateCoordinator.acquire(path, { storeGeneration: "generation-1", nestedLockNames: ["receipt-store"] })).rejects.toThrow(/lease|owned|exists/u);
    const moduleUrl = pathToFileURL(join(process.cwd(), "packages", "sidecar", "dist", "index.js")).href;
    const child = `import { StateCoordinator } from ${JSON.stringify(moduleUrl)}; try { const owner = await StateCoordinator.acquire(process.argv[1], { storeGeneration: "generation-1", nestedLockNames: ["receipt-store"] }); await owner.close(); process.exit(2); } catch (error) { if (!/lease|owned|exists/u.test(String(error?.message))) throw error; }`;
    await expect(execFileAsync(process.execPath, ["--input-type=module", "--eval", child, path])).resolves.toMatchObject({ stderr: "" });
    await first.close();
  });

  it("requires exact prior ownership and the complete lock inventory for offline handoff", async () => {
    const root = await mkdtemp(join(tmpdir(), "sidecar-coordinator-recovery-"));
    const path = join(root, "state");
    const first = await StateCoordinator.acquire(path, { storeGeneration: "generation-1", nestedLockNames: ["nonce-store", "receipt-store"] });
    const ownership = await first.withMutation((capability) => first.receiptStoreLockOwnership(capability));
    await expect(StateCoordinator.recoverAbandoned(path, {
      offlineExclusive: true,
      expectedOwnerToken: ownership.ownerToken,
      expectedRootIdentityDigest: ownership.rootIdentityDigest,
      storeGeneration: ownership.storeGeneration,
      nestedLockNames: ["receipt-store"],
    })).rejects.toThrow(/inventory|mismatch/u);
    const recovered = await StateCoordinator.recoverAbandoned(path, {
      offlineExclusive: true,
      expectedOwnerToken: ownership.ownerToken,
      expectedRootIdentityDigest: ownership.rootIdentityDigest,
      nextOwnerToken: "recovered-owner",
      storeGeneration: ownership.storeGeneration,
      nestedLockNames: ["nonce-store", "receipt-store"],
    });
    await expect(first.withMutation(() => undefined)).rejects.toThrow(/ownership changed/u);
    await expect(recovered.withMutation((capability) => recovered.receiptStoreLockOwnership(capability))).resolves.toMatchObject({ ownerToken: "recovered-owner" });
    await recovered.close();
  });

  it("allows mutation only through the live coordinator capability", async () => {
    const { coordinator, requests } = await harness();
    await expect(requests.reserve({} as never, reservationInput())).rejects.toThrow(/capability|owner/u);
    let nestedOwnership: unknown;
    let staleCapability: unknown;
    await coordinator.withMutation(async (capability) => {
      staleCapability = capability;
      nestedOwnership = coordinator.receiptStoreLockOwnership(capability);
      expect(nestedOwnership).toMatchObject({ storeGeneration: "generation-1", ownerToken: expect.any(String), rootIdentityDigest: expect.stringMatching(/^[a-f0-9]{64}$/u) });
    });
    await expect(requests.reserve(staleCapability as never, reservationInput())).rejects.toThrow(/capability/u);
    await expect(coordinator.withMutation(async (capability) => coordinator.receiptStoreLockOwnership(capability))).resolves.toBeDefined();
    await coordinator.close();
    expect(nestedOwnership).toBeDefined();
  });

  it("binds receipt-store nested locks to the exact coordinator owner", async () => {
    const { root, coordinator } = await harness();
    let staleStore: FileReceiptStore | undefined;
    await coordinator.withMutation(async (capability) => {
      const ownership = coordinator.receiptStoreLockOwnership(capability);
      let observed: unknown;
      const store = new FileReceiptStore(join(root, "receipts"), {
        lockOwnership: ownership,
        faultInjector: async (point) => {
          if (point === "lock:after-publish") observed = JSON.parse(await readFile(join(root, "receipts", ".store-lock.json"), "utf8"));
        },
      });
      staleStore = store;
      await store.cleanupStaging({ offlineExclusive: true });
      expect(observed).toEqual({ version: 2, ...ownership });
      expect(() => new FileReceiptStore(join(root, "invalid-receipts"), { lockOwnership: { ...ownership, ownerToken: "independent token" } as never })).toThrow(/ownership/u);
    });
    await expect(staleStore!.cleanupStaging({ offlineExclusive: true })).rejects.toThrow(/capability|authorized/u);
    await coordinator.close();
  });
});
