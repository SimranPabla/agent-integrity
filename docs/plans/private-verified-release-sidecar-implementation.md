# Private Agent Integrity Sidecar Implementation Plan

> **Review state:** Proposed implementation sequence accompanying the sidecar architecture. Tasks use checkbox (`- [ ]`) syntax for auditable execution tracking.

**Goal:** Build a same-host, Unix-socket Agent Integrity sidecar that authenticates one CAGE client, verifies a frozen evidence bundle, creates and consumes a real signed receipt through a recoverable durable phase machine, and releases only the exact verified response bytes.

**Architecture:** Add a private `@agent-integrity/sidecar` workspace package using Node.js built-ins for Unix-socket HTTP and worker threads. Keep canonical envelope and receipt schemas unchanged. Extend `@agent-integrity/core` only with deterministic receipt construction and read-only recovery inspection, then compose closed request parsing, HMAC authentication, private snapshotting, durable idempotency, receipt recovery, exact-byte release, and bounded transport in focused modules.

**Tech Stack:** TypeScript 5.8, Node.js 22 built-ins (`http`, `crypto`, `worker_threads`, `fs/promises`), existing Agent Integrity protocol/core/SDK packages, Vitest, Ed25519, HMAC-SHA-256, RFC 8785/JCS canonical JSON.

**Frozen design:** `docs/architecture/private-verified-release-sidecar.md` in this review change. Implementation must not begin until that document is approved and frozen in repository history.

**Public base used for schema-diff checks:** `880ea482fce4a6ee8914f8922a8ab12cc0ba1a59`.

**Execution rule:** Complete tasks in order. For every task, prove the red test before implementation, keep the named commit isolated, and require separate specification and code-quality reviews before the next task. Do not modify either public JSON schema or any CAGE repository file.

---

## Chunk 1: Security and storage primitives

### Task 1: Add the private sidecar package and closed wire protocol

**Files:**
- Modify: `package.json`
- Create: `packages/sidecar/package.json`
- Create: `packages/sidecar/tsconfig.json`
- Create: `packages/sidecar/src/protocol.ts`
- Create: `packages/sidecar/src/index.ts`
- Create: `packages/sidecar/tests/protocol.test.ts`
- Modify: `packages/core/src/index.ts`
- Modify: `packages/core/tests/schema/envelope-schema.test.ts`

- [ ] **Step 1: Write failing protocol tests**

Test exact acceptance and rejection for:

```ts
const validRequest = {
  serviceProtocolVersion: "1",
  requestId: "req-123",
  idempotencyKey: "idem-123",
  bundleId: "bundle-123",
  envelope: validEnvelope(),
};

expect(parseCanonicalServiceRequest(Buffer.from(canonicalJson(validRequest)), MAX_BODY)).toEqual(validRequest);
expect(() => parseCanonicalServiceRequest(Buffer.from('{"requestId":"a","requestId":"b"}'), MAX_BODY)).toThrow(/duplicate/u);
expect(() => parseCanonicalServiceRequest(Buffer.from(JSON.stringify({ ...validRequest, extra: true })), MAX_BODY)).toThrow(/unknown/u);
expect(() => parseCanonicalServiceRequest(Buffer.from(` ${canonicalJson(validRequest)}`), MAX_BODY)).toThrow(/canonical/u);
```

Also test maximum body and envelope bytes, identifier alphabets/lengths, UTF-8 errors, arrays/null, unsupported version, envelope structural rejection, escaped lone UTF-16 surrogates at every nesting depth, and mutation of the returned value. The parser must return a deeply frozen object and the request digest must be lowercase SHA-256 over the accepted canonical body bytes.

Define and test closed private service-response types at the same boundary. `PASS` has the exact wrapper fields `serviceProtocolVersion`, `requestId`, `status`, `verification`, `receipt`, and `releasedResponse`; `REVIEW`/`BLOCKED` omit `releasedResponse`; `RELEASE_REFUSED` has the exact wrapper fields `serviceProtocolVersion`, `requestId`, `status`, `verification`, `receipt`, and closed `release { status, code, retryable }`; technical errors contain only protocol version, optional safely parsed request ID, and `{ code, retryable }`. Validate the nested verification and receipt against the unchanged public types/schemas, require response `requestId` to equal the admitted request ID, require normal outcome statuses to agree, require `RELEASE_REFUSED` to retain a PASS receipt with no bytes and stable non-PASS release status, require RFC 8785 canonical equality of wrapper and receipt verification for every receipt-bearing response, require the receipt envelope digest to match the request, reject unknown fields, and bound every string/array/body before persistence or transport.

- [ ] **Step 2: Run the tests and prove the red state**

Run: `npx vitest run packages/sidecar/tests/protocol.test.ts`

Expected: FAIL because `@agent-integrity/sidecar` and `protocol.ts` do not exist.

- [ ] **Step 3: Add the workspace package**

Add `packages/sidecar` to the root build/typecheck project sequence. Use:

```json
{
  "name": "@agent-integrity/sidecar",
  "version": "0.1.0-alpha.2",
  "private": true,
  "type": "module",
  "dependencies": {
    "@agent-integrity/core": "0.1.0-alpha.2",
    "@agent-integrity/protocol": "0.1.0-alpha.2",
    "@agent-integrity/sdk": "0.1.0-alpha.2"
  },
  "engines": { "node": ">=22" }
}
```

Keep it private for the first same-host implementation. Do not add a web framework or runtime dependency. Do not add the `bin` entry until Task 9 creates `cli.ts`. Update the root build/typecheck scripts explicitly, then run `npm install --package-lock-only --ignore-scripts` and assert `package-lock.json` contains the `packages/sidecar` workspace entry.

- [ ] **Step 4: Implement the closed parser and digest**

`protocol.ts` owns only:

```ts
export const SIDECAR_PROTOCOL_VERSION = "1" as const;
export interface ServiceRequest {
  serviceProtocolVersion: "1";
  requestId: string;
  idempotencyKey: string;
  bundleId: string;
  envelope: IntegrityEnvelope;
}
export function parseCanonicalServiceRequest(raw: Uint8Array, maxBytes: number): ServiceRequest;
export function serviceRequestDigest(request: ServiceRequest): string;
export function parseCanonicalServiceResponse(raw: Uint8Array, limits: ResponseLimits): ServiceResponse;
```

Use the repository's canonical JSON function after a duplicate-key-aware JSON scan. Recursively reject lone UTF-16 surrogate code units before canonicalization. Reject bytes unless parsing and re-canonicalization reproduce the exact input. `serviceRequestDigest()` accepts only the exact deeply frozen object identity returned by `parseCanonicalServiceRequest()` and returns the stored digest of those admitted raw bytes; it rejects forged or structurally identical caller-created objects and never reserializes the request. Export the existing throwing `assertIntegrityEnvelope()` validator from `@agent-integrity/core`, add an export regression test, and call it before returning an admitted request. Do not substitute `verifyEnvelope()` because malformed structure must be rejected rather than converted into a verdict. Do not accept optional aliases or coerce values.

- [ ] **Step 5: Run focused and compatibility checks**

Run:

```bash
npx vitest run packages/sidecar/tests/protocol.test.ts
npm run typecheck
npm test -- --run packages/protocol/tests/types.test.ts packages/core/tests/canonical-json.test.ts
node -e 'const p=require("./package-lock.json"); if(!p.packages["packages/sidecar"]) process.exit(1)'
```

Expected: all pass; `schemas/*.json` remain byte-identical.

- [ ] **Step 6: Commit**

```bash
git add package.json package-lock.json packages/sidecar packages/core/src/index.ts packages/core/tests/schema/envelope-schema.test.ts
git commit -m "feat(sidecar): add closed service protocol"
```

### Task 2: Add exact HMAC authentication and durable nonce replay protection

**Files:**
- Create: `packages/sidecar/src/auth.ts`
- Create: `packages/sidecar/src/nonce-store.ts`
- Create: `packages/sidecar/src/durable-json.ts`
- Create: `packages/sidecar/tests/auth.test.ts`
- Create: `packages/sidecar/tests/nonce-store.test.ts`

- [ ] **Step 1: Write failing authentication-vector tests**

Freeze a golden vector for the length-delimited MAC input. Test exact success plus wrong client, wrong key ID, wrong body, timestamp skew, future timestamp, malformed 43-character unpadded base64url, and old/new HMAC keys during an overlap window. Raw duplicate-header rejection belongs exclusively to Task 9 because normalized `AuthHeaders` cannot represent duplicates.

The test helper must construct the MAC input as:

```ts
const prefix = Buffer.from("agent-integrity-sidecar-auth-v1", "ascii");
const fields = [method, path, serviceProtocolVersion, clientId, keyId, timestamp, nonce, bodyDigest];
const encoded = Buffer.concat([prefix, ...fields.flatMap((field) => {
  const bytes = Buffer.from(field, "utf8");
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return [length, bytes];
})]);
```

Mutate each field independently, including method, request path, protocol version, and exact canonical body digest, and require authentication failure.

- [ ] **Step 2: Write failing nonce-store tests**

Prove create-once replay rejection across two store instances and two child processes, including the same client nonce presented under two different simultaneously active HMAC key IDs during rotation. Also prove file/directory mode `0600`/`0700`, file and directory sync failure handling, state-size bounds, exact quota accounting, bounded closed record parsing, malformed/unknown fields, parent/root substitution and symlink attacks, and retention beyond the complete timestamp-skew window.

- [ ] **Step 3: Run tests and prove the red state**

Run: `npx vitest run packages/sidecar/tests/auth.test.ts packages/sidecar/tests/nonce-store.test.ts`

Expected: FAIL with missing modules.

- [ ] **Step 4: Implement shared durable JSON publication**

`durable-json.ts` provides bounded read, create-once publication through a same-directory temporary file and hard link, mode checks, file sync, directory sync where supported, and fault injection. It must reject symlinks/nonregular files and never treat a falsy thrown value as success.

- [ ] **Step 5: Implement authentication and nonce consumption**

Expose:

```ts
export interface AuthHeaders {
  clientId: string;
  keyId: string;
  timestampMs: string;
  nonce: string;
  mac: string;
}
export function authenticateRequest(options: AuthenticateRequestOptions): AuthenticatedRequest;
export class FileNonceStore {
  consume(record: NonceRecord): Promise<void>;
}
```

The authentication options include the exact HTTP method, path, service protocol version, raw canonical body digest, captured host time, and immutable HMAC registry snapshot. Use `timingSafeEqual`; validate all lengths before comparison. The server must first perform bounded, side-effect-free closed parsing and canonical-byte validation to obtain the request's protocol version and stored raw-body digest. It then verifies the MAC. Only after successful constant-time comparison may the request enter the mutation coordinator and call `FileNonceStore.consume()`. Tests prove malformed or bad-MAC requests cannot publish nonce records, while a valid MAC with a conflicting nonce fails as replay. Authentication and durable nonce consumption are separate explicit steps so no caller can describe an unconsumed authentication as admitted. The create-once nonce uniqueness key is `SHA256(len32be(UTF8(clientId)) || UTF8(clientId) || len32be(UTF8(nonce)) || UTF8(nonce))` and deliberately excludes HMAC key ID; retain the authenticated key ID only as closed record metadata so rotation cannot make a nonce reusable.

- [ ] **Step 6: Run focused tests and typecheck**

Run:

```bash
npx vitest run packages/sidecar/tests/auth.test.ts packages/sidecar/tests/nonce-store.test.ts
npm run typecheck
```

Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add packages/sidecar/src/auth.ts packages/sidecar/src/nonce-store.ts packages/sidecar/src/durable-json.ts packages/sidecar/tests
git commit -m "feat(sidecar): authenticate requests and block replay"
```

### Task 3: Validate and privately snapshot evidence bundles

**Files:**
- Create: `packages/sidecar/src/bundle.ts`
- Create: `packages/sidecar/src/path-boundary.ts`
- Create: `packages/sidecar/tests/bundle.test.ts`
- Create: `packages/sidecar/tests/fixtures/bundle/manifest.json`
- Create: `packages/sidecar/tests/fixtures/bundle/project/integrity/policy.yaml`
- Create: `packages/sidecar/tests/fixtures/bundle/project/integrity/trusted-config.json`
- Create: `packages/sidecar/tests/fixtures/bundle/project/integrity/decisions.yaml`
- Create: `packages/sidecar/tests/fixtures/bundle/project/docs/approved.md`

- [ ] **Step 1: Write failing adversarial filesystem tests**

Cover valid copy plus absolute/traversal/separator/nested bundle IDs, request-ID/bundle-ID/envelope-digest mismatch, unknown fields at every level, wrong evidence-completeness statement, invalid timestamp, nullable expiry, `publishedAt >= expiresAt`, collected-after-publication, future publication beyond skew, expiry equality, expired bundle, excessive lifetime, root swap, symlink, hardlink, FIFO/nonregular file, duplicate/unsorted manifest path or source root, extra/missing file, non-canonical raw manifest bytes, manifest self-digest error, accidental `manifest.json` file-list inclusion, size/digest mismatch, mutation during copy, broad permissions, manifest/root/file/path/byte limits, and destination collision. Prove a snapshot accepted before expiry remains the sole recovery input after incoming-bundle expiry. The authenticated HTTP request is the single authoritative envelope; no envelope copy exists inside the bundle and no receipt run ID exists yet. Tests bind every envelope source, policy, decision, and trusted-configuration reference to manifest-listed files.

- [ ] **Step 2: Prove the red state**

Run: `npx vitest run packages/sidecar/tests/bundle.test.ts`

Expected: FAIL with missing `bundle.ts`.

- [ ] **Step 3: Implement bounded manifest validation**

Implement exactly the architecture's `BundleManifestV1` schema: `version`, `bundleId`, `requestId`, `envelopeDigest`, the three trusted relative paths, sorted unique `allowedSourceRoots`, closed `evidenceCompleteness { attesterId, statement: "complete-for-request", collectedAt }`, `publishedAt`, required non-null `expiresAt`, sorted unique exhaustive `files { path, bytes, sha256 }`, and `manifestDigest`, with no additional fields. Enforce the declared identifier/path/timestamp grammar and configurable limits capped at 1 MiB manifest bytes, 64 roots, 10,000 files, and 1,024 UTF-8 bytes per path. Against one injected fresh host time require collected-at no later than publication, publication before expiry, publication no more than configured future skew (hard ceiling 60 seconds), current time strictly before expiry, and total bundle lifetime no greater than the configured limit (hard ceiling 15 minutes). Require exact equality with the authenticated request's bundle ID and request ID and with SHA-256 of its canonical envelope. Require the three trusted paths and every envelope source in `files`; every source must fall under exactly one allowed root. `manifest.json` is excluded from its own file list. Require its raw bytes to equal RFC 8785 re-canonicalization before removing only `manifestDigest`, canonicalizing the remaining object, and checking the declared digest. Open and stat each listed file without following links; require one link; compare parent/root identity before and after the copy.

- [ ] **Step 4: Implement private snapshot publication**

Copy only manifest-listed regular files into a new sidecar-owned `0700` staging directory, verify while streaming, sync contents/directories, then atomically publish a content-addressed snapshot directory. Define snapshot identity as SHA-256 of canonical JSON containing the incoming manifest digest and verified ordered file records. An existing destination is accepted only after bounded full validation of its private manifest and every file against that exact identity; any mismatch fails closed and nothing is overwritten. Return only a deeply frozen snapshot descriptor and trusted file paths inside `<snapshot>/project/`.

- [ ] **Step 5: Run focused and existing trusted-source tests**

Run:

```bash
npx vitest run packages/sidecar/tests/bundle.test.ts packages/core/tests/adversarial/path-boundary.test.ts packages/core/tests/verification/trusted-source-verification.test.ts
npm run typecheck
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add packages/sidecar/src/bundle.ts packages/sidecar/src/path-boundary.ts packages/sidecar/tests
git commit -m "feat(sidecar): snapshot trusted evidence bundles"
```

### Task 4: Make receipt construction deterministic and recovery-inspectable

**Files:**
- Create: `packages/core/src/receipts/build-receipt.ts`
- Create: `packages/core/src/receipts/receipt-store-records.ts`
- Create: `packages/core/src/receipts/receipt-output-boundary.ts`
- Modify: `packages/core/src/receipts/create-receipt.ts`
- Modify: `packages/core/src/receipts/file-receipt-store.ts`
- Modify: `packages/core/src/index.ts`
- Create: `packages/core/tests/receipts/receipt-recovery.test.ts`
- Modify: `packages/core/tests/receipts/receipt.test.ts`

- [ ] **Step 1: Write failing deterministic-builder tests**

Prove that the same explicit run ID, nonce, created/expires times, signer, envelope, and already-live-verified result produce the same signed receipt/digest. Prove any changed input changes the digest. The pure builder receives no filesystem path or `TrustedVerificationContext`; `createReceipt()` must still perform live trusted verification before calling it.

- [ ] **Step 2: Write failing read-only inspection tests**

Require exact read-only inspection methods:

```ts
store.inspectIssuedByDigest(digest): Promise<AlphaIntegrityReceipt | undefined>
store.inspectIssuedByRunId(runId): Promise<AlphaIntegrityReceipt | undefined>
store.inspectConsumed(digest): Promise<ConsumedReceiptRecord | undefined>
store.inspectCapacity(): Promise<{ used: number; maximum: number }>
```

Each inspection method must validate record schema, receipt digest, run/nonce bindings, and store ownership. It must not issue, consume, roll back, overwrite, complete output, or silently repair anything. Output recovery is a separate mutating operation with this exact boundary:

```ts
const output = await ReceiptOutputBoundary.open(configuredAbsoluteRoot);
await store.completeReceiptFile(digest, output, safeRelativeName);
```

`ReceiptOutputBoundary` holds a validated root identity and accepts only one safe relative filename. The store never accepts an arbitrary absolute output path from a request. Durable sidecar state stores only that validated relative name plus the boundary's canonical root-identity digest; every recovery reopens the configured root, requires the same identity, and passes the relative name through `ReceiptOutputBoundary` again.

Also require caller-supplied service transaction identity at issuance and one terminal close operation:

```ts
store.issue(receipt, { transactionId }): Promise<void>
store.closeIssuedReceipt(receiptDigest, { transactionId, closedAt, reasonCode }): Promise<void>
```

The store persists the exact caller-supplied transaction ID in transaction, quota, run, nonce, issued, consumed, and closed records; it never creates a second random transaction ID. Close is create-once, accepts only a bounded stable reason code, rejects a mismatched transaction or any consumed marker, and makes later consume fail. Consume rejects an existing closed marker.

- [ ] **Step 3: Prove the red state**

Run: `npx vitest run packages/core/tests/receipts/receipt-recovery.test.ts`

Expected: FAIL with missing builder/inspection APIs.

- [ ] **Step 4: Extract a deterministic pure receipt builder**

Move canonical body/signature/digest construction into `buildReceipt()`. Keep `createReceipt()` responsible for live verification, store issuance, and output completion through an explicit `ReceiptOutputBoundary` plus safe relative output name. `buildReceipt()` accepts only explicit frozen inputs and the live verification result, not a trusted context. Update the CLI/tests to construct their intended output boundary explicitly. Do not change either receipt schema or verdict semantics.

- [ ] **Step 5: Add bounded inspection APIs**

Add `receipt-store-records.ts` with closed parsers for issued, consumed, closed, quota, transaction, recovery, and cleanup records. Reject unknown fields, malformed JSON, oversized values, invalid embedded receipts, and binding mismatches. Change receipt issuance to require the validated service transaction ID instead of calling `randomUUID()` internally, propagate it to every record, and add the create-once close operation plus consumed/closed mutual-exclusion checks. Add `receipt-output-boundary.ts` to validate/open the configured output root, pin its identity, reject symlink/root replacement, and publish only create-once relative receipt files. Use existing store locks for coherent inspection and bounded directory traversal; in sidecar mode every such lock must receive the state coordinator's exact root owner token, store generation, and root identity and must not mint an independent token. Return deep-frozen validated data. `inspectCapacity()` reports used/maximum records without deleting tombstones.

- [ ] **Step 6: Add crash-window tests**

Fault-inject after store issuance but before output completion, and after output publication/directory sync but before the caller observes success. Rebuild the identical receipt from frozen inputs and inspect the issued record. Prove transaction-ID mismatch fails, consumed-versus-closed races have exactly one winner, closed receipts cannot be consumed, consumed receipts cannot be closed, and crash recovery preserves the original transaction ID. `completeReceiptFile()` may accept an existing relative output only after the boundary revalidates its root identity and bounded, closed parsing proves the file is byte-equivalent to the issued receipt; otherwise it fails closed and never overwrites. Add absolute/traversal/separator name, symlink, root-substitution, and conflicting-file tests. Prove a second issuance is rejected.

- [ ] **Step 7: Run receipt, SDK release, and schema regressions**

Run:

```bash
npx vitest run packages/core/tests/receipts packages/sdk/tests/release.test.ts packages/core/tests/schema/envelope-schema.test.ts
npm run typecheck
git diff 880ea482fce4a6ee8914f8922a8ab12cc0ba1a59 --exit-code -- schemas/integrity-envelope.schema.json schemas/integrity-receipt.schema.json
```

Expected: all pass and both schemas unchanged.

- [ ] **Step 8: Commit**

```bash
git add packages/core/src packages/core/tests/receipts
git commit -m "feat(core): expose deterministic receipt recovery"
```

## Chunk 2: Durable request orchestration

### Task 5: Implement the versioned request-state store and idempotency tombstones

**Files:**
- Create: `packages/sidecar/src/request-state.ts`
- Create: `packages/sidecar/src/request-store.ts`
- Create: `packages/sidecar/src/state-coordinator.ts`
- Create: `packages/sidecar/src/private-object-store.ts`
- Create: `packages/sidecar/tests/request-store.test.ts`

- [ ] **Step 1: Write failing phase-transition tests**

Define these exact discriminated records:

```text
reserved: client ID, store generation, idempotency-key hash, exact request digest (identical to the authenticated canonical-body digest), request ID, transaction ID, and content-addressed private canonical-request object ID
verified: reserved + private snapshot ID, envelope digest, verification digest, complete canonical verification/outcome
receipt-prepared: verified + fresh signing time, content-addressed complete public receipt-trust snapshot ID/digest, key ID/public metadata, deterministic run ID/nonce, created/expires times, audience, purpose, engine version, max lifetime, validated relative receipt-output name, pinned output-root identity digest, trusted-context digest, and exact prepared PASS bytes/digest when applicable
receipt-issued: receipt-prepared + complete signed receipt, receipt digest, and shared service transaction ID
pass-consumed: receipt-issued + exact validated consumed-marker identity and consumption time
release-refused: receipt-issued + exact validated closed-marker identity and exact stable `RELEASE_REFUSED` response preserving the signed receipt and containing no release bytes
result-committed: terminal response, outcome, receipt expiry, delivery deadline, and response-byte retention state
tombstone: client/store generation/idempotency-key hash + permanent request-digest binding + terminal/expired state, with no response bytes
```

Prove only this branch-specific graph: `reserved -> verified -> receipt-prepared -> receipt-issued`; an original REVIEW/BLOCKED outcome goes directly from `receipt-issued -> result-committed`; a prospective PASS continues through either `pass-consumed -> result-committed` or `release-refused -> result-committed`. Reject unknown fields, oversized records, skipped/reversed phases, owner changes, transaction-ID changes, and contradictory duplicate publication.

- [ ] **Step 2: Write failing idempotency tests**

Prove new reservation publishes the exact bounded canonical request bytes into a `0700` content-addressed private object store before the `reserved` record; every recovery recomputes `SHA256(exact canonical request-body bytes)` and requires it to equal both the authenticated body digest and the recorded request digest. No second hash, concatenation, or parsed-object serialization is permitted. Prove exact retry, changed-digest conflict, completed retry without bundle access, expired result returning no bytes, cleanup of request/registry objects only after terminal delivery expiry, compaction to a tombstone, same-key reuse rejection after cleanup, and explicit new-generation scoping.

- [ ] **Step 3: Write failing cross-process and durability tests**

Use child processes to prove one state-root process lease covering nonce, request, idempotency, receipt, transaction, and snapshot mutations; second-process rejection; no automatic lock stealing; every nested receipt-store lock inheriting the exact root owner token/generation/root identity; rejection of an independently tokened, missing, or unexpected nested lock; offline exact-token recovery; all-or-nothing append-only owner-token handoff over the bounded complete lock set; file/directory sync failure handling; bounded record/capacity accounting; and fail-closed ambiguous state. Prove partial handoff cannot authorize mutation. The in-memory transaction queue is added separately in Task 8 but may mutate state only through the lease-owning coordinator.

- [ ] **Step 4: Implement state unions and validation**

`request-state.ts` owns types, closed parsers, transition table, and digests only. `private-object-store.ts` owns bounded create-once canonical request and public registry snapshots, closed reads, digest validation, strict permissions, reference-aware cleanup, and no source-byte storage. `state-coordinator.ts` owns the lifetime state-root lease, immutable owner token, single mutation capability, bounded nested-lock inventory, and validated all-or-nothing offline token handoff; it exposes no arbitrary or partial unlock operation. Receipt-store locks accept only that coordinator-owned token in sidecar mode and never mint a second token. `request-store.ts` reuses `durable-json.ts` and owns phase publication, lookup, tombstone compaction, and capacity only when called with that mutation capability.

- [ ] **Step 5: Run focused tests**

Run:

```bash
npx vitest run packages/sidecar/tests/request-store.test.ts
npm run typecheck
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add packages/sidecar/src/request-state.ts packages/sidecar/src/request-store.ts packages/sidecar/src/state-coordinator.ts packages/sidecar/src/private-object-store.ts packages/sidecar/tests/request-store.test.ts
git commit -m "feat(sidecar): persist recoverable request phases"
```

### Task 6: Implement configuration, permissions, and key lifecycle

**Files:**
- Create: `packages/sidecar/src/config.ts`
- Create: `packages/sidecar/src/key-registry.ts`
- Create: `packages/sidecar/tests/config.test.ts`
- Create: `packages/sidecar/tests/permissions.test.ts`

- [ ] **Step 1: Write failing closed-config tests**

Test required absolute socket and bundle paths plus one sidecar-owned state root with fixed nonce/request/receipt/transaction/snapshot children, one configured CAGE client, numeric bounds, audience/purpose, store generation, HMAC overlap, receipt registry, and rejection of unknown fields/environment fallbacks.

- [ ] **Step 2: Write failing permission and key tests**

Prove startup rejection for symlinks, wrong Unix owner/group/mode, shared signing key access, mismatched private/public key, invalid metadata, expired/revoked active key, missing historical public keys, and unsafe socket directory. Use injectable identity/stat readers so tests do not require root.

- [ ] **Step 3: Write failing reload and time-selection tests**

Prove invalid reload preserves the old snapshot; valid reload atomically swaps HMAC/receipt registries; key selection at an injected current time rejects expired/revoked entries; returned complete public registry/config snapshots are canonical and immutable; and private recovery keys remain addressable by key ID until no prepared transaction references them. Lifecycle cases involving publication of the content-addressed public registry snapshot or an in-flight transaction belong to Task 8.

- [ ] **Step 4: Implement immutable configuration snapshots**

Parse from an explicit file only. Deep-freeze the validated snapshot. Expose atomic `loadInitial()` and `reload()`; never expose raw secret bytes through returned configuration, errors, or logging.

- [ ] **Step 5: Run focused tests**

Run: `npx vitest run packages/sidecar/tests/config.test.ts packages/sidecar/tests/permissions.test.ts && npm run typecheck`

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add packages/sidecar/src/config.ts packages/sidecar/src/key-registry.ts packages/sidecar/tests
git commit -m "feat(sidecar): validate identities and key lifecycle"
```

### Task 7: Run pure trusted verification in a cancellable worker

**Files:**
- Create: `packages/sidecar/src/trusted-context.ts`
- Create: `packages/sidecar/src/verification-worker.ts`
- Create: `packages/sidecar/src/verification-runner.ts`
- Create: `packages/sidecar/tests/trusted-context.test.ts`
- Create: `packages/sidecar/tests/verification-runner.test.ts`

- [ ] **Step 1: Write failing trusted-context parser tests**

Load the trusted policy and trusted-config files only from the private snapshot. Require exact closed keys for `allowedRoots`, `decisionRegistryPath`, `maxSourceBytes`, and `maxTotalSourceBytes`; confine every path under `<snapshot>/project`; bind policy roots and decision path to the manifest and envelope; enforce byte/item limits; deep-freeze the resulting `TrustedVerificationContext`; and reject the CLI's current unsafe-cast behavior.

- [ ] **Step 2: Write failing worker-boundary tests**

Prove PASS/REVIEW/BLOCKED against the existing conformance fixtures, maximum serialized input/output, worker exception, invalid worker output, timeout termination, parent abort before completion, and no receipt/request-store mutation capability in the worker message contract.

- [ ] **Step 3: Prove the red state**

Run: `npx vitest run packages/sidecar/tests/trusted-context.test.ts packages/sidecar/tests/verification-runner.test.ts`

Expected: FAIL with missing runner.

- [ ] **Step 4: Implement trusted-context loading and the worker**

`trusted-context.ts` is the only owner of snapshot policy/config parsing. The worker receives only the canonical envelope, a closed immutable worker message containing private-snapshot paths/limits, and no receipt/store capability. It calls the trusted-context loader and `verifyTrustedEnvelope()`, then returns canonical verification data. The parent terminates it at the pure-verification deadline and treats every malformed/error/timeout result as a technical failure without receipt mutation.

- [ ] **Step 5: Run focused and verifier regression tests**

Run:

```bash
npx vitest run packages/sidecar/tests/trusted-context.test.ts packages/sidecar/tests/verification-runner.test.ts packages/core/tests/verification
npm run typecheck
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add packages/sidecar/src/trusted-context.ts packages/sidecar/src/verification-worker.ts packages/sidecar/src/verification-runner.ts packages/sidecar/tests/trusted-context.test.ts packages/sidecar/tests/verification-runner.test.ts
git commit -m "feat(sidecar): isolate cancellable verification"
```

### Task 8: Implement the recoverable verify-sign-consume-release service

**Files:**
- Create: `packages/sidecar/src/service.ts`
- Create: `packages/sidecar/src/recovery.ts`
- Create: `packages/sidecar/src/consumed-release-recovery.ts`
- Create: `packages/sidecar/src/scheduler.ts`
- Create: `packages/sidecar/src/readiness.ts`
- Create: `packages/sidecar/tests/service.test.ts`
- Create: `packages/sidecar/tests/service-crash.test.ts`
- Create: `packages/sidecar/tests/scheduler.test.ts`
- Modify: `packages/core/src/receipts/recheck-receipt.ts`
- Modify: `packages/core/src/index.ts`
- Modify: `packages/core/tests/receipts/receipt-recovery.test.ts`

- [ ] **Step 1: Write failing outcome and exact-byte tests**

Prove PASS returns the signed receipt plus base64 of only the exact bytes returned by `releaseVerifiedReceipt()`. REVIEW/BLOCKED return signed receipts without bytes. A prospective PASS that fails fresh release recheck returns the exact closed `RELEASE_REFUSED` response with the already-issued receipt, stable non-PASS release status/code, and no bytes. Re-encode/decode and SHA-256 compare the response, including non-ASCII and newline cases. Require RFC 8785 canonical equality of wrapper and receipt verification for every receipt-bearing response, require the decoded sidecar bytes and digest to equal the original request envelope's exact UTF-8 `response.content` bytes, and require `receipt.envelopeDigest` to equal the independently recomputed request-envelope digest.

- [ ] **Step 2: Write failing ordered-lifecycle tests**

Instrument collaborators and assert:

```text
bounded closed parse/digest -> authenticate MAC -> enter mutation coordinator
-> consume auth nonce -> idempotency lookup/reserve with one transaction ID
-> bundle snapshot -> pure verify -> verified -> fresh key check
-> receipt-prepared -> receipt issue with same transaction ID -> receipt-issued
-> PASS release -> inspect consumed/closed state
-> pass-consumed or release-refused -> result-committed -> bind request ID -> return
```

Prove bad-MAC input cannot consume a nonce, queue timeout occurs before nonce mutation, every response request ID equals the admitted request ID, and completed retries stop after idempotency lookup without touching the removed bundle.

- [ ] **Step 3: Write failing crash-matrix tests**

Fault-inject after every durable phase and specifically after receipt-store issuance before `createReceipt()` returns, after consumption before phase publication, and after result commit before response. Extract a pure, non-consuming `validateTrustedReceipt()` in core for signature/binding/live-source verification at a supplied time. Add this sidecar-internal API, not an SDK-wide skip flag:

```ts
recoverConsumedRelease({
  request, verification, receipt, context, frozenTrustSnapshot,
  receiptStore, expectedTransactionId, expectedConsumedAt,
  preparedResponseDigest, now,
}): Promise<ReleaseResult>
```

The function must load the exact consumed marker internally through `FileReceiptStore.inspectConsumed()`, validate receipt/run/nonce/digest/shared-transaction/time bindings, call `validateTrustedReceipt()` at the fresh `now`, call `releaseVerifiedResponse()` to recollect trusted inputs, compare exact response bytes with `preparedResponseDigest`, and only then return. It never accepts a caller-provided consumed record and never calls consume. For a non-PASS return from `releaseVerifiedReceipt()`, inspect the store: a matching consumed marker uses this recovery path; a proven unconsumed receipt is closed create-once and advances through `release-refused`; missing, contradictory, or unreadable evidence makes readiness false. Persist the exact canonical `RELEASE_REFUSED` response, including the already-issued signed receipt, before transport. Restart with the same state and prove the initial response and every authenticated retry are byte-identical, with no second receipt, no second consumption, and no unproved release. A receipt that expires before consumption is closed and releases no bytes; never reuse the prepared signing time as the recovery/recheck time.

- [ ] **Step 4: Write failing time/key/idempotency tests**

Cover expiry/revocation during verification before preparation, publication and digest validation of the complete frozen public registry snapshot, rotation after preparation, unrelated registry changes after preparation, key loss during recovery, canonical-request object mutation/missing object, result expiry, tombstone reuse, expired completed requests never reopening the bundle/verifier/signer/store, client disconnect, queue timeout, store quota, receipt quota, and ambiguous state readiness failure. Inject a fresh release clock value and prove a receipt that expires after preparation but before release is rejected; the prepared signing time may reconstruct the receipt but must never be used as release/recheck time or consumed timestamp.

- [ ] **Step 5: Implement the bounded scheduler and readiness latch**

`scheduler.ts` owns the bounded in-memory queue and one active mutation capability at a time. It acquires that capability from the lifetime lease-owning `state-coordinator`; queue timeout and `503` overflow happen before nonce consumption. The active request retains the capability through terminal or durably recoverable phase publication, including pure verification in this first one-client profile, so no request or recovery worker can interleave cross-store transitions. `readiness.ts` aggregates validated configuration, root lease ownership, key availability, store capacity, socket identity, and ambiguous recovery state; it exposes reason codes without paths or secrets.

- [ ] **Step 6: Implement the service and recovery dispatcher**

Keep `service.ts` as dependency-injected orchestration; it must not open sockets or parse OS configuration. Before every recovery step, load the content-addressed canonical request and, when prepared, complete frozen public registry snapshot; verify each against its recorded digest. `recovery.ts` implements this explicit dispatch table:

```text
reserved -> snapshot and verify from persisted canonical request
verified -> fresh key check, persist public registry snapshot, prepare
receipt-prepared -> reconstruct, inspect, and complete exact issuance
receipt-issued REVIEW/BLOCKED -> result-committed
receipt-issued PASS -> release and inspect store; matching consumed -> pass-consumed; proven unconsumed non-PASS -> close and release-refused
pass-consumed -> store-backed recoverConsumedRelease, then result-committed
release-refused -> result-committed with the preserved signed receipt, exact stable release-refusal response, and no release bytes
result-committed -> bounded redelivery or expired response
unknown/contradictory -> readiness false and offline recovery only
```

Unknown or contradictory state returns a stable technical error and sets readiness false.

- [ ] **Step 7: Run all service/core/SDK tests**

Run:

```bash
npx vitest run packages/sidecar/tests/service.test.ts packages/sidecar/tests/service-crash.test.ts packages/sidecar/tests/scheduler.test.ts packages/core/tests/receipts packages/sdk/tests/release.test.ts
npm run typecheck
```

Expected: all pass.

- [ ] **Step 8: Commit**

```bash
git add packages/sidecar/src/service.ts packages/sidecar/src/recovery.ts packages/sidecar/src/consumed-release-recovery.ts packages/sidecar/src/scheduler.ts packages/sidecar/src/readiness.ts packages/sidecar/tests packages/core/src/receipts/recheck-receipt.ts packages/core/src/index.ts packages/core/tests/receipts/receipt-recovery.test.ts
git commit -m "feat(sidecar): recover verify and release transactions"
```

## Chunk 3: Private transport, operations, and final proof

### Task 9: Add the bounded Unix-socket HTTP server and health model

**Files:**
- Create: `packages/sidecar/src/server.ts`
- Create: `packages/sidecar/src/health.ts`
- Create: `packages/sidecar/src/cli.ts`
- Create: `packages/sidecar/src/recovery-authorization.ts`
- Create: `packages/sidecar/README.md`
- Create: `packages/sidecar/tests/server.test.ts`
- Create: `packages/sidecar/tests/socket-permissions.test.ts`
- Create: `packages/sidecar/tests/cli.test.ts`
- Create: `packages/sidecar/tests/support/test-config.ts`

- [ ] **Step 1: Write failing HTTP/UDS tests**

Test only `POST /v1/verify-release`, `GET /health/live`, and `GET /health/ready`. Cover duplicate raw auth headers, header byte/count limits, chunked oversized body, early disconnect, read timeout, unsupported method/path/content type, malformed canonical JSON, excessive envelope decisions/evidence/claims/sections/findings, queue overflow with `Retry-After`, and response-size bound. Assert the exact design mapping: `200` for persisted PASS/REVIEW/BLOCKED/RELEASE_REFUSED outcomes, `400` malformed/protocol, `401` auth/replay, `409` idempotency conflict, `413` body/header limit, `422` bundle/resource validation, `503` unavailable/queue/storage, `500` internal failure, with no receipt/release mutation on any technical failure.

- [ ] **Step 2: Write failing socket lifecycle tests**

Prove a root-parented socket directory owned by the sidecar identity with client-group mode `0710`; CAGE can traverse but cannot list/create/replace/unlink entries; the sidecar can bind and unlink only a stale Unix socket with the exact expected owner/group; regular files, symlinks, foreign sockets, and changed directory identity fail closed. Prove post-bind socket owner/group/mode `0660`, second-server failure, shutdown stop-accepting behavior, verification-worker cancellation, state-changing grace period, and nonzero unsafe shutdown.

- [ ] **Step 3: Write failing CLI recovery tests**

Generate temporary absolute roots and test-only Ed25519/HMAC files through `test-config.ts`. Define a protected recovery-authorization JSON file with exact closed fields: version, action `recover`, store generation, canonical state-root identity, exact abandoned-lock owner token, issued/expiry times, and unique authorization nonce. The CLI receives only its absolute path through `--authorization-file`; the file must be owned by root or the sidecar identity, mode `0400`, outside request-controlled roots, unexpired, and exact-bound to the existing store lock/generation/root. On successful recovery, atomically publish a consumed-authorization audit marker keyed by its nonce before removing the source file; replay is rejected. Prove `check-config` success/failure exit codes; `recover --offline-exclusive --authorization-file /absolute/path` refuses while the socket/live writer is active, never guesses or steals a lock, rejects wrong/expired/replayed authorization, fails on ambiguous ownership, redacts paths/token, and succeeds only against the deliberately abandoned store named by the authorization.

- [ ] **Step 4: Implement server and health checks**

Use `node:http` over `server.listen(socketPath)`. Validate the sidecar-owned `0710` socket directory before touching the socket path; remove only a validated stale socket owned by the configured sidecar UID and client GID; bind; set socket mode `0660`; and revalidate the directory and socket identities. Collect raw headers without normalization loss, stream and cap the body, perform bounded closed canonical parsing before MAC verification, and write only the persisted service result. Liveness checks event-loop response only. Readiness checks configuration, keys, the state-root lease, capacity, bundle/snapshot roots, socket identity, and absence of ambiguous recovery state without issuing/consuming a receipt.

- [ ] **Step 5: Implement the CLI entrypoint**

Support only:

```text
integrity-sidecar serve --config /absolute/path/config.json
integrity-sidecar recover --config /absolute/path/config.json --offline-exclusive --authorization-file /absolute/path/recovery.json
integrity-sidecar check-config --config /absolute/path/config.json
```

Never accept secret values on argv. Log structured codes and request IDs only; redact paths and content.

- [ ] **Step 6: Add the private binary and minimal package README**

Add `"bin": { "integrity-sidecar": "./dist/cli.js" }` only now that `cli.ts` exists. The README states that this workspace package is private and excluded from the public npm publish set, documents the three commands, and contains no production-readiness claim.

- [ ] **Step 7: Run transport and CLI tests**

Run:

```bash
npx vitest run packages/sidecar/tests/server.test.ts packages/sidecar/tests/socket-permissions.test.ts packages/sidecar/tests/cli.test.ts
npm run build
```

Expected: tests pass and build succeeds. CLI tests create all absolute roots and secrets in a temporary directory; no committed config contains a usable secret.

- [ ] **Step 8: Commit**

```bash
git add packages/sidecar/src packages/sidecar/tests packages/sidecar/package.json packages/sidecar/README.md
git commit -m "feat(sidecar): serve authenticated Unix socket API"
```

### Task 10: Add end-to-end conformance, adversarial, and clean-install proof

**Files:**
- Create: `packages/sidecar/tests/e2e.test.ts`
- Create: `packages/sidecar/tests/adversarial.test.ts`
- Create: `packages/sidecar/tests/support/test-service.ts`
- Create: `scripts/test-sidecar-unix-identities.sh`
- Create: `scripts/test-sidecar-no-network.sh`
- Modify: `tests/conformance/package-exports.test.ts`
- Modify: `scripts/check-packages.mjs`

- [ ] **Step 1: Write the end-to-end test first**

Start a real sidecar on a temporary Unix socket with generated test-only Ed25519/HMAC keys and copied fixture bundles. Send raw authenticated HTTP requests and prove PASS/REVIEW/BLOCKED/RELEASE_REFUSED, response/source/decision mutation, missing/expired/future/overlong bundle, invalid config, timeout, auth replay, idempotent byte-identical redelivery, result expiry, and restart recovery.

- [ ] **Step 2: Add adversarial process/filesystem tests**

Use child processes for simultaneous requests, second writer, crash at each receipt phase, malformed worker output, output/key/store permission attacks, bundle root swap, excessive decisions/evidence/claims/sections/findings, store exhaustion, and bounded log/error disclosure. Tests must assert no private key, HMAC key, raw response, source bytes, or host path appears in stdout/stderr.

- [ ] **Step 3: Run focused end-to-end tests**

Run: `npx vitest run packages/sidecar/tests/e2e.test.ts packages/sidecar/tests/adversarial.test.ts`

Expected: all pass.

- [ ] **Step 4: Add real Linux identity and no-network proofs**

`test-sidecar-unix-identities.sh` requires Linux root and uses temporary numeric `cage`/`agent-integrity` identities and a shared client group to prove: CAGE can connect to the socket and read only its HMAC copy; CAGE cannot read the signing key, snapshots, request state, or receipt store; the sidecar identity can read its signing key/state; and unrelated identities cannot connect. `test-sidecar-no-network.sh` runs the end-to-end UDS verdict test inside an isolated network namespace with no external interface, proving verdict calculation needs no outbound network. Both scripts trap cleanup. If the execution environment cannot run them, the result is INCONCLUSIVE and the PR is not called runtime-ready.

- [ ] **Step 5: Prove private-package and schema compatibility**

Keep `packages/sidecar/package.json` private. Update `check-packages.mjs` to assert the public publish set remains exactly `protocol`, `core`, `sdk`, and `cli`, while separately building and smoke-running `packages/sidecar/dist/cli.js`. Update package-export tests to assert emitted sidecar JavaScript exists but it is absent from the public pack list. Do not create or publish a sidecar tarball.

Run:

```bash
npm run build
npm run typecheck
npm test
npm run pack:check
git diff 880ea482fce4a6ee8914f8922a8ab12cc0ba1a59 --exit-code -- schemas/integrity-envelope.schema.json schemas/integrity-receipt.schema.json
```

Expected: all pass; schemas unchanged.

- [ ] **Step 6: Commit the tested implementation checkpoint**

```bash
git add packages/sidecar/tests scripts/test-sidecar-unix-identities.sh scripts/test-sidecar-no-network.sh tests/conformance/package-exports.test.ts scripts/check-packages.mjs
git commit -m "test(sidecar): prove private runtime boundaries"
```

Record this exact SHA as `TESTED_CODE_COMMIT`.

- [ ] **Step 7: Prove clean-install reproducibility at the committed SHA**

Create a detached worktree at `TESTED_CODE_COMMIT`, confirm no `node_modules`/`dist`, run `npm ci --ignore-scripts`, `npm run build`, `npm run verify`, `npm run pack:check`, and both Linux security scripts. Write exact commit, Node/npm versions, commands, counts, schema hashes, and security-script outcomes to a temporary machine-readable evidence file outside the repository for Task 11. Do not modify the tested worktree.


### Task 11: Document operation, recovery, limitations, and the CAGE follow-up contract

**Files:**
- Modify: `packages/sidecar/README.md`
- Modify: `docs/integrations/cage-provider-06-contract.md`
- Create: `docs/results/2026-09-18-private-sidecar-result.md`
- Create: `scripts/check-sidecar-secrets.sh`
- Create: `packages/sidecar/tests/fixture-secrets.test.ts`
- Modify: `README.md`
- Create an operator-local runbook outside the repository at a deployment-approved path supplied through `SIDECAR_RUNBOOK_PATH`; never commit host-specific usernames, home directories, or secret values.

- [ ] **Step 1: Write package and integration documentation**

Document exact guarantee, separate Unix identities, socket/HMAC/signing-key provisioning, evidence bundle ownership and expiry, response contract including `RELEASE_REFUSED`, verdict routing, phase machine, retry rules, key rotation, store generation, health, limits, and explicit non-goals. Define the complete closed CAGE trust-manifest and key-entry schema, generation, freshness, rollback rejection, atomic refresh, cache-expiry behavior, and fail-closed unknown/revoked key handling. Require 1-128 sorted unique key entries, exact 32-byte raw Ed25519 public-key encoding, validity/revocation ordering, bounded profile strings/durations, no unknown fields, and fresh-clock acceptance. Persist the accepted `(generation, manifestDigest)` pair; reject lower generations and equal-generation digest conflicts. Freeze the trust-manifest signature profile as Ed25519 with a pinned authority key ID, a 32-byte raw public key encoded as 43-character unpadded canonical base64url, a domain-separated preimage containing the raw 32-byte manifest digest, and a 64-byte signature encoded as 86-character unpadded canonical base64url; require rejection tests for schema, limit, ordering, algorithm, key-ID, padding, encoding, and decoded-length mismatch in the later CAGE integration PR. State that CAGE runtime integration is a separate PR against the current partner layout. Before admission CAGE must bind the response request ID, require canonical equality of wrapper and signed receipt verification, verify expected issuer/audience/purpose/engine version and trusted policy, enforce receipt and key validity/revocation at a fresh host time, verify the envelope digest and signed receipt, route `RELEASE_REFUSED` as non-admitting while preserving its signed receipt, and dispatch only the exact returned bytes.

- [ ] **Step 2: Write the result document from executed evidence**

Import the temporary machine-readable proof from Task 10 and record the fixed base, `TESTED_CODE_COMMIT`, protected-file/schema hashes, tool versions, exact commands/results, test counts, review findings/fixes, clean-install evidence, remaining assumptions, and pass/fail/inconclusive decision. The result document is a later evidence commit and must not claim to embed its own final tree hash. Do not claim CAGE runtime integration, production deployment, commercial adoption, legal correctness, or distributed exactly-once behavior.

- [ ] **Step 3: Write and safely verify the offline runbook**

Include installation, Unix users/groups, directories and modes, secret locations without values, start/stop/status, health checks, logs, key/HMAC rotation, store capacity, offline recovery, backup/restore, rollback, and destructive warnings. Mark commands requiring root or a future service manager as unverified unless actually exercised.

- [ ] **Step 4: Run documentation and secret checks**

Create `scripts/check-sidecar-secrets.sh` with `set -euo pipefail`. It must require `command -v rg`, collect every added/modified tracked file since the public base commit through a NUL-delimited filename array, append the operator-supplied external runbook path, verify every target is readable, and run the pattern scan while distinguishing exit `1` (no matches) from exit `0` (secret found) and exit `>1` (scanner/read failure). Run:

```bash
test -n "${SIDECAR_RUNBOOK_PATH:-}"
scripts/check-sidecar-secrets.sh "$SIDECAR_RUNBOOK_PATH"
npx vitest run packages/sidecar/tests/fixture-secrets.test.ts
git diff --check
npm run verify
npm run pack:check
```

The fixture-structure test rejects private-key, HMAC-secret, token, or credential fields in committed JSON/YAML fixtures. Expected: no secret material, scanner/read errors fail the command, no whitespace errors, and all project checks pass.

- [ ] **Step 5: Request final independent reviews**

Dispatch one specification reviewer against the frozen design and one security/code-quality reviewer against the full diff, including the external runbook. Resolve every blocking finding through test-first follow-up commits and rerun the clean-install proof against a new named tested-code commit if code changed.

- [ ] **Step 6: Commit documentation**

```bash
git add README.md packages/sidecar/README.md packages/sidecar/tests/fixture-secrets.test.ts scripts/check-sidecar-secrets.sh docs/integrations/cage-provider-06-contract.md docs/results/2026-09-18-private-sidecar-result.md
git commit -m "docs(sidecar): publish operation and evidence"
```

- [ ] **Step 7: Prepare but do not publish the PR**

Verify a clean tree and prepare a PR titled `feat(sidecar): add private verified-release service`. The body must separate observed evidence, limitations, and the later CAGE adapter PR. Show the exact diff, checks, and PR body to the project owner before any push or external PR creation.
