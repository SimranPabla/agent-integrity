# Agent Integrity Private Sidecar Design

**Status:** Proposed for cross-project review; revision 4 incorporates public review findings and is pending re-review
**Date:** 2026-09-21
**Agent Integrity base:** `880ea482fce4a6ee8914f8922a8ab12cc0ba1a59`
**CAGE reference base:** `7ab1acd57ce8bf9ae7e7501254330f54ebc7028a`
**CAGE evidence:** merged conformance PR `google/cybernetic-agent-governance-engine#205`

## 1. Decision and purpose

Build an Agent Integrity-owned, same-host private HTTP sidecar that exposes one authenticated, recoverable verify, sign, consume, and exact-byte-release operation for a canonical `1-alpha` response envelope.

This design informs whether Agent Integrity can become a reusable runtime service without weakening its local-first guarantees or moving trusted verifier behavior into CAGE.

The first implementation targets one host and one trusted CAGE client. It uses HTTP over a Unix domain socket. A future Kubernetes same-pod deployment may reuse the application protocol, but distributed storage, multi-tenant isolation, public networking, and cross-host operation are outside this design.

## 2. Evidence and current state

Known facts:

- CAGE Provider 06 already expects an HTTP verification seam.
- CAGE PR #205 proved that the existing Agent Integrity `1-alpha` response envelope represents and verifies the frozen CAGE response fixture without schema changes.
- The public Agent Integrity repository currently supports in-process TypeScript and CLI integration. It does not expose a production HTTP service.
- `createReceipt()` re-verifies trusted live inputs before issuing an Ed25519 receipt.
- `releaseVerifiedReceipt()` re-verifies the envelope, authenticates and consumes a receipt, and returns response content only for an unchanged `PASS`.
- `FileReceiptStore` provides local, create-once receipt issuance and one-time consumption. Its guarantees require one protected, shared, monotonic local filesystem store.
- The CAGE mock `/receipt` response is not a cryptographically valid production receipt.

Unknowns this implementation must resolve:

- whether the complete service transaction can fail closed across process, storage, and client retry boundaries;
- whether request authentication and durable idempotency can be added without changing the public envelope or receipt schemas;
- whether exact-byte release can be represented safely over HTTP without CAGE reconstructing the verified text.

## 3. Experiment brief

### Decision

Based on this result, decide whether to proceed with a separate CAGE runtime-adapter PR against the Agent Integrity sidecar.

### Hypothesis

A same-host sidecar can authenticate one CAGE client, copy one allowlisted incoming evidence bundle into a sidecar-owned private snapshot, verify a canonical envelope, issue and consume a real signed receipt, and return exact releasable bytes only for `PASS`, while every malformed, ambiguous, replayed, unavailable, or storage-failure path releases no bytes.

### Baseline

The baseline is the current local CLI integration plus CAGE's mock HTTP endpoint. The CLI performs real verification but has no service lifecycle, request authentication, recoverable receipt/release phase machine, or retry contract. The mock provides HTTP plumbing but not real signed receipts.

### Experiment type

Capability and reliability only. This experiment does not test adoption, commercial value, production availability, legal correctness, action safety, evidence completeness, or multi-host operation.

### Primary metric

Required sidecar scenarios producing the exact expected HTTP status, Agent Integrity verdict, receipt behavior, and release-byte behavior divided by total required scenarios.

### Thresholds

- **Pass:** 100% of required scenarios match the frozen contract; clean-install verification passes; public envelope and receipt schemas remain byte-identical; no non-PASS or technical-failure path returns releasable bytes.
- **Fail:** any invalid, REVIEW, BLOCKED, replayed, unauthenticated, timed-out, or storage-failure path returns response bytes; receipt or idempotency binding can be changed without detection; or the design requires weakening the canonical protocol.
- **Inconclusive:** the trusted bundle collector or sidecar-owned private-snapshot boundary cannot be represented without granting broad filesystem authority.

### Predetermined actions

- **Pass:** design a separate CAGE Provider 06 runtime PR against the frozen sidecar contract.
- **Fail:** stop CAGE runtime work and repair the Agent Integrity service boundary first.
- **Inconclusive:** stop until CAGE defines a trusted evidence collector and snapshot owner.

## 4. Scope

### In scope

- a new private sidecar package owned by Agent Integrity;
- HTTP/1.1 over a Unix domain socket;
- OS filesystem permissions plus request HMAC authentication;
- one logical `POST /v1/verify-release` operation backed by a recoverable durable phase machine;
- `GET /health/live` and `GET /health/ready`;
- strict request, response, path, size, and time bounds;
- allowlisted incoming-bundle resolution and sidecar-owned private snapshot creation;
- real `verifyTrustedEnvelope`, `createReceipt`, and `releaseVerifiedReceipt` execution;
- real Ed25519 receipt signing;
- durable local receipt, replay, authentication-nonce, and idempotency state;
- exact response bytes encoded as base64 only for a valid `PASS`;
- structured metadata-only logging and minimal metrics;
- clean-start, retry, crash-window, mutation, replay, and failure tests.

### Out of scope

- changes to the `1-alpha` envelope schema or `2-alpha` receipt schema;
- arbitrary action authorization;
- public TCP exposure;
- anonymous requests;
- multi-tenant operation;
- distributed receipt or replay storage;
- cross-host consistency;
- Kubernetes manifests or cloud deployment;
- arbitrary URL fetching or object-store access;
- semantic truth, legal, regulatory, completeness, safety, or recommendation-quality claims;
- CAGE runtime code changes;
- replacement of CAGE's current mock in this repository change.

## 5. Trust, operating-system, and ownership boundaries

### CAGE host

The trusted CAGE host owns:

- selection and freezing of the final response artifact;
- observation and collection of approved sources;
- preservation of the active decision registry;
- policy selection;
- evidence-completeness attestation;
- construction of the canonical envelope;
- publication of a complete incoming evidence bundle beneath the configured bundle root;
- possession of the sidecar request-authentication secret;
- release of only bytes returned by the sidecar.

The model, agent payload, and envelope cannot choose trusted roots, the bundle root, signing key, authentication key, receipt store, replay store, key registry, host clock, or release behavior.

### Agent Integrity sidecar

The sidecar owns:

- strict transport parsing and authentication;
- mapping an opaque bundle ID to one allowlisted bundle directory;
- independently loading trusted policy and trusted configuration from that bundle;
- recollecting actual source and decision bytes;
- verification outcome;
- receipt signing;
- receipt issuance and consumption;
- durable idempotency and replay records;
- returning releasable bytes only after successful receipt consumption.

### Filesystem and operating system

The sidecar and CAGE run as separate Unix identities:

- `agent-integrity`: owns the sidecar process, signing key, trusted key registry, receipt state, request state, and private snapshots;
- `cage`: owns the CAGE process and incoming evidence-bundle staging area;
- `agent-integrity-clients`: contains only the `cage` and `agent-integrity` identities and grants access to the Unix socket.

Required ownership and modes:

- socket parent: root-owned, group `agent-integrity-clients`, mode `0750`;
- Unix socket: owner `agent-integrity`, group `agent-integrity-clients`, mode `0660`;
- sidecar configuration and public trust registry: owner `agent-integrity`, mode no broader than `0600`;
- Ed25519 private key: owner `agent-integrity`, mode `0400`;
- receipt, replay, idempotency, nonce, and snapshot roots: owner `agent-integrity`, mode `0700`;
- CAGE incoming-bundle root: owner `cage`, group `agent-integrity-clients`, mode `0750`;
- CAGE HMAC key copy: owner `cage`, mode `0400`;
- sidecar HMAC key copy: owner `agent-integrity`, mode `0400`.

The two HMAC copies are provisioned from the same secret-manager value; CAGE cannot read the sidecar copy, and CAGE never receives the Ed25519 private key. Startup uses `lstat`, `realpath`, ownership, group, type, and mode checks and rejects symlinks or unexpected parents for the socket, keys, configuration, and state roots.

CAGE publishes bundles into its incoming root. The sidecar does not treat chmod as immutability. After authenticating the request, it validates the exhaustive manifest and copies the declared files into a newly created sidecar-owned private snapshot. Verification reads only that private snapshot. The CAGE host remains trusted for evidence completeness and can intentionally omit evidence; the snapshot boundary prevents later agent or CAGE-process mutation from changing bytes during verification.

One active sidecar process may own a configured state root. A compromised operating system, root user, or malicious trusted CAGE host remains outside the guarantee.

## 6. Package boundary

Add a private workspace package:

```text
packages/sidecar/
```

It depends on:

- `@agent-integrity/protocol` for transport-adjacent protocol types;
- `@agent-integrity/core` for verification and receipt issuance;
- `@agent-integrity/sdk` for authenticated receipt consumption and exact response release;
- Node.js built-in HTTP, crypto, filesystem, path, and stream APIs.

The initial package is not published to npm. It produces one executable entry point:

```text
agent-integrity-sidecar
```

Using Node's built-in HTTP server avoids introducing a framework dependency into the trust boundary. The package must remain independently testable and must not move service concerns into `packages/core`.

## 7. Deployment model

The service listens on one configured Unix domain socket. It does not listen on TCP in the initial release.

Required configuration is loaded from a host-owned JSON file passed by path at process start:

- socket path;
- evidence-bundle root;
- receipt/replay state root;
- idempotency state root;
- authentication nonce state root;
- configured client IDs and HMAC key IDs with sidecar-owned secret-file paths;
- Ed25519 private-key file path;
- signing key ID, issuer, audience, purpose, and engine version;
- trusted public-key registry;
- maximum request, envelope, source, total-source, response, and finding sizes;
- receipt lifetime;
- request timestamp skew;
- graceful-shutdown timeout.

Secrets are read from files, never command-line values, URLs, request bodies, logs, or committed configuration.

Startup fails closed if configuration, Unix identities, group membership, keys, socket ownership, bundle root, or state directories are missing, malformed, symlinked, broadly accessible, or inconsistent.

## 8. Evidence-bundle contract

The request contains an opaque safe identifier:

```text
bundleId = [A-Za-z0-9][A-Za-z0-9._-]{0,127}
```

The sidecar resolves it only as a direct child of the configured bundle root. Absolute paths, separators, traversal, symlinks, nested arbitrary paths, and URL-like values are rejected.

One incoming bundle contains:

```text
<bundle-root>/<bundle-id>/
  manifest.json
  project/
    integrity/policy.yaml
    integrity/decisions.yaml
    integrity/trusted-config.json
    docs/
      ...approved source files...
```

`manifest.json` is host-created metadata containing:

- bundle version;
- bundle ID;
- request/run identity;
- trusted relative policy path;
- trusted relative decision-registry path;
- trusted relative configuration path;
- allowed source roots;
- evidence-completeness attestation;
- publication timestamp;
- optional expiry;
- an exhaustive ordered file list containing every allowed regular file below `project/`, including policy, decision, trusted-configuration, and approved-source files, with each relative path, byte size, and SHA-256 digest;
- a manifest digest calculated as SHA-256 over canonical JSON with the `manifestDigest` field omitted.

`manifest.json` is not an entry in its own exhaustive file list. Its raw bytes must themselves be RFC 8785 canonical JSON and must equal byte-for-byte re-canonicalization of the parsed closed manifest. The sidecar then removes only `manifestDigest`, canonicalizes the remaining object, and verifies that SHA-256 against the declared lowercase-hex `manifestDigest`. This avoids a circular self-digest while authenticating the complete manifest bytes through one reproducible rule.

The sidecar requires the HTTP request body to be canonical JSON and checks that its envelope refers only to files in the exhaustive manifest. It rejects unlisted extra files, missing files, duplicate paths, absolute paths, traversal, symlinks, non-regular files, and files with link counts other than one. It verifies every declared size and digest while copying into a new private snapshot. It checks incoming file identity and metadata before and after each copy and rechecks the incoming root identity before publication of the private snapshot.

The private snapshot receives a sidecar-generated manifest binding the incoming manifest digest, the copied exhaustive file list, and the private snapshot identity. The sidecar then opens only the private snapshot's `project/` directory as `projectRoot` and supplies independently loaded policy and trusted configuration to the core verifier. The request cannot override manifest trust fields.

The trusted CAGE host must publish the incoming bundle with an atomic directory rename before sending the request and must not mutate it afterward. The sidecar does not claim this makes CAGE-owned bytes immutable; private snapshot copying establishes the service-owned verification bytes. Platforms still inherit the documented parent-path race limitations of portable Node.js filesystem APIs. The design therefore trusts the same-host OS and CAGE host while protecting against agent-controlled paths and post-copy mutation.

## 9. Request authentication

The initial service uses defense in depth:

1. Unix socket filesystem permissions restrict which local identity may connect.
2. Each request carries an HMAC-SHA256 authentication header set.

Required headers:

- `X-Agent-Integrity-Client`: fixed configured client ID;
- `X-Agent-Integrity-Key-Id`: configured HMAC key ID;
- `X-Agent-Integrity-Timestamp`: UTC epoch milliseconds;
- `X-Agent-Integrity-Nonce`: safe unique identifier;
- `X-Agent-Integrity-Signature`: base64url HMAC-SHA256.

All identifiers use `[A-Za-z0-9][A-Za-z0-9._-]{0,127}`. The timestamp is exactly 13 ASCII decimal digits representing UTC epoch milliseconds. The signature is unpadded canonical base64url encoding of exactly 32 bytes and therefore exactly 43 characters.

The MAC preimage starts with the ASCII domain separator `agent-integrity-sidecar-auth-v1` and then encodes each field as a four-byte unsigned big-endian byte length followed by the exact field bytes. Field order is fixed:

- method;
- request path;
- service protocol version;
- client ID;
- HMAC key ID;
- timestamp;
- nonce;
- lowercase 64-character SHA-256 of the exact canonical request-body bytes.

The HTTP body must be RFC 8785 canonical JSON. The sidecar parses it and requires byte equality with re-canonicalization; this rejects duplicate JSON keys, alternate whitespace, and non-canonical number/string encodings. It inspects raw headers and rejects duplicate authentication headers case-insensitively rather than accepting a runtime-combined value.

The sidecar:

- reads the HMAC secret from a protected file;
- rejects timestamps outside the configured skew window;
- rejects unknown, inactive, expired, or revoked HMAC key IDs;
- decodes the signature to a fixed-length buffer before constant-time comparison;
- consumes the authentication nonce through a durable create-once store before verification;
- never logs the secret, signature, full body, envelope, sources, or response.

Authentication failure returns no Agent Integrity receipt and no release bytes.

Every retry uses a fresh authentication timestamp, nonce, and signature. It retains the same idempotency key and exact canonical request body. HMAC rotation adds a new active key ID and may retain a bounded previous verification key during an explicit overlap window; secrets are reloaded only through the validated configuration-reload procedure.

## 10. Recoverable service API contract

### `POST /v1/verify-release`

Request body:

```json
{
  "serviceProtocolVersion": "1",
  "requestId": "safe-id",
  "idempotencyKey": "safe-id",
  "bundleId": "safe-id",
  "envelope": {}
}
```

The envelope remains the canonical Agent Integrity `1-alpha` envelope. Service transport fields do not enter the envelope schema.

Successful HTTP responses serialize one of these closed structural types as canonical JSON:

```ts
type PassResponse = Readonly<{
  serviceProtocolVersion: "1";
  requestId: SafeId;
  status: "PASS";
  verification: IntegrityResult & { status: "PASS" };
  receipt: AlphaIntegrityReceipt;
  releasedResponse: Readonly<{
    encoding: "base64";
    sha256: LowercaseSha256;
    bytes: CanonicalPaddedBase64;
  }>;
}>;

type RefusalResponse = Readonly<{
  serviceProtocolVersion: "1";
  requestId: SafeId;
  status: "REVIEW" | "BLOCKED";
  verification: IntegrityResult;
  receipt: AlphaIntegrityReceipt;
}>;
```

The service parser and serializer use closed discriminated response types:

- `PASS` contains exactly `serviceProtocolVersion`, `requestId`, `status`, `verification`, `receipt`, and `releasedResponse`;
- `REVIEW` and `BLOCKED` contain exactly `serviceProtocolVersion`, `requestId`, `status`, `verification`, and `receipt` and must omit `releasedResponse`;
- `verification` must validate as the closed public `IntegrityResult 1-alpha` type;
- `receipt` must validate as the closed public `IntegrityReceipt 2-alpha` schema;
- wrapper `status`, `verification.status`, and `receipt.verification.status` must be identical;
- `receipt.envelopeDigest` must equal the digest independently recomputed from the exact request envelope;
- `releasedResponse` contains exactly `encoding`, `sha256`, and `bytes`; `encoding` is `base64`, `sha256` is lowercase hexadecimal SHA-256, and `bytes` is canonical padded base64 within the configured response limit.

For `REVIEW` and `BLOCKED`, the sidecar returns `verification` and a signed `receipt`, but omits `releasedResponse`.

Technical failures return one of two closed shapes and no other fields:

```json
{
  "serviceProtocolVersion": "1",
  "requestId": "safe-id",
  "error": {
    "code": "STABLE_ENUM_VALUE",
    "retryable": false
  }
}
```

If `requestId` was not safely parsed, it is omitted. `error` contains exactly `code` and `retryable`; `code` is one of `INVALID_REQUEST`, `UNSUPPORTED_PROTOCOL`, `AUTHENTICATION_FAILED`, `REPLAY_DETECTED`, `BUNDLE_UNAVAILABLE`, `BUNDLE_INVALID`, `IDEMPOTENCY_CONFLICT`, `PAYLOAD_TOO_LARGE`, `RESOURCE_LIMIT`, `RESULT_EXPIRED`, `STORAGE_UNAVAILABLE`, `SIGNING_UNAVAILABLE`, `VERIFIER_FAILURE`, `SERVICE_UNAVAILABLE`, or `INTERNAL_FAILURE`. No message, path, exception text, or attacker-controlled value is reflected. A technical failure contains no receipt or release bytes unless the transaction had already durably completed and is being returned through an authenticated idempotent retry.

The endpoint is one logical operation but is not described as a single atomic filesystem transaction. Receipt issuance, receipt consumption, and result publication are separate durable operations and are coordinated through the recoverable phase machine below.

### Health endpoints

- `GET /health/live`: the process event loop can respond. It does not assert verifier readiness.
- `GET /health/ready`: configuration, private signing key, HMAC key, trusted key registry, bundle root, state roots, and socket ownership are usable. It performs no destructive receipt operation.

Health endpoints expose no secret or source metadata. Readiness failure returns non-2xx.

## 11. Verify, sign, consume, and release phase machine

For a new authenticated request:

1. Stream and bound the raw request body.
2. Authenticate exact body bytes and durably consume the authentication nonce.
3. Parse a closed service request schema.
4. Define `requestDigest` as exactly the lowercase 64-character SHA-256 body digest already authenticated in the MAC: `SHA256(exact RFC 8785 canonical request-body bytes)`. Do not hash the parsed request again or concatenate a second representation.
5. Inspect the client-scoped idempotency binding before resolving the bundle. If a matching `result-committed` record exists and its delivery window remains open, return the persisted result immediately. If its delivery window is closed, return the persisted expired outcome without response bytes. A different request digest conflicts permanently within the store generation.
6. For a new request, reserve the idempotency key and persist phase `reserved` using create-once storage. A matching nonterminal request enters recovery from its proven phase.
7. Only for a new or resumable pre-verification request, resolve and validate the evidence bundle and create the private snapshot.
8. Load trusted policy and config from the private snapshot.
9. Run pure trusted verification in a dedicated worker. The worker may be terminated at the verification deadline because it has no receipt or result-store mutation authority.
10. Persist phase `verified` with the canonical verification result and private snapshot ID.
11. Immediately before receipt preparation, capture a fresh host signing time and the current fully validated receipt-key registry. Check that the selected signing key is present, matches its public key and metadata, is not revoked, and is valid at that fresh time.
12. Derive the run ID and receipt nonce deterministically from the store generation, client ID, idempotency binding, and request digest. Persist phase `receipt-prepared` before signing. It contains every immutable `createReceipt()` input or content-addressed reference required to reconstruct it exactly: run ID, nonce, created/expires times, signing key ID and public metadata, audience, purpose, engine version, maximum lifetime, receipt output path, envelope and verification digests, private snapshot ID, trusted-context digest, and, for prospective `PASS`, the exact prepared response bytes and digest.
13. Call `createReceipt()` with only the frozen `receipt-prepared` inputs. Ed25519 signing and canonical receipt construction are deterministic for those inputs.
14. Persist phase `receipt-issued` with the receipt digest and complete signed receipt. If `createReceipt()` fails or the process crashes after store issuance but before returning, recovery reconstructs the exact receipt from `receipt-prepared`, inspects the store by deterministic run ID or receipt digest, and completes the existing issuance; it never selects new inputs or issues a second receipt.
15. For `PASS`, capture a fresh host release time immediately before release and call `releaseVerifiedReceipt()` using the same envelope, trusted context, frozen receipt-key registry, that fresh release time, and the shared receipt store. The prepared signing time is used only to reconstruct the deterministic receipt; it is never reused for expiry checking or the consumed timestamp.
16. Persist phase `pass-consumed` only after proving the receipt-store consumed marker belongs to this receipt and service transaction.
17. Encode the response returned by `releaseVerifiedReceipt()` as exact UTF-8 bytes and base64; compare those bytes and their SHA-256 with both the prepared response and the original request envelope's exact UTF-8 `response.content` bytes.
18. Persist phase `result-committed` containing the complete service result, retention deadline, and receipt expiry.
19. Return only the persisted committed result.

The sidecar never returns draft bytes directly from the request. It returns only bytes produced by `releaseVerifiedReceipt()`.

Implementation requires minimal read-only receipt-store recovery APIs that validate store records before returning them:

- inspect an issued receipt by run ID or receipt digest;
- inspect whether a matching receipt digest is consumed;
- recover the stored issued receipt after output-file completion failure;
- report bounded capacity without deleting uniqueness tombstones.

These APIs do not allow mutation, un-consumption, overwrite, or reuse. They exist only to prove which durable phase completed after a crash. Receipt construction must also expose or reuse one deterministic pure builder so recovery can reconstruct the exact signed receipt from `receipt-prepared` before asking the store to complete an already-started issuance.

## 12. Idempotency and crash behavior

The idempotency key is scoped to the configured client ID.

- First request reserves `clientId + idempotencyKey` and binds it to the request digest.
- An authenticated retry uses a fresh authentication nonce and signature. With the same idempotency key and exact body digest, it returns the exact persisted completed result.
- A retry with the same key and a different digest returns a conflict and no release bytes.
- Idempotency lookup occurs before any evidence-bundle access. A matching completed retry therefore does not depend on the incoming bundle still existing.
- Recovery advances only when the phase journal and validated receipt-store state prove the next phase. It never reruns receipt consumption blindly.
- Ambiguous or contradictory durable state makes readiness fail and requires an offline-exclusive operator recovery.

The completed result must be durably stored before the HTTP response is written. If the client disconnects after completion, an authenticated retry receives the same stored result.

For a PASS, repeated delivery is authenticated transport redelivery, not receipt reuse. Redelivery is allowed only to the same client and request digest, only until the earlier of the configured result-retention deadline or receipt expiry. After expiry, the service returns no response bytes and never re-executes that idempotency key. Unlinking expired result bytes is best-effort confidentiality cleanup; secure physical deletion is not guaranteed by ordinary filesystems.

The initial request-state store is local filesystem state with create-once records, atomic publication, directory synchronization where supported, strict permissions, bounded records, and explicit offline recovery. It does not claim distributed exactly-once behavior.

Durable phases are:

- `reserved`: client, idempotency key hash, exact request digest, request ID, and transaction ID;
- `verified`: reserved record plus verification digest, outcome, and private snapshot ID;
- `receipt-prepared`: verified record plus every frozen receipt-construction input, fresh signing time, registry digest, deterministic run ID and nonce, output path, expiry, and prepared response bytes/digest for PASS;
- `receipt-issued`: receipt-prepared record plus receipt digest and complete signed receipt;
- `pass-consumed`: receipt-issued record plus validated consumed marker identity;
- `result-committed`: terminal service response, retention deadline, and outcome.

Each phase is a versioned closed record with a maximum size. Publication uses create-new or atomic same-directory promotion plus file and directory synchronization where supported. Phase transitions validate the previous record and transaction ID.

The authentication-nonce store uses create-once records keyed by `SHA256(len32be(UTF8(clientId)) || UTF8(clientId) || len32be(UTF8(nonce)) || UTF8(nonce))`. HMAC key ID is authenticated and retained as record metadata, but it is not part of the uniqueness key. The same client nonce is therefore rejected across every simultaneously active or overlapping HMAC key. Records also contain the authenticated timestamp and body digest and are retained beyond the maximum timestamp-skew window. Result bytes and full result records have a configured retention bound no later than receipt expiry. Cleanup replaces an expired full idempotency record with a compact generation-scoped tombstone that permanently binds the client ID, idempotency-key hash, and request digest and records the terminal/expired state. The same key can never bind to another digest or trigger a second receipt within that store generation. Cleanup runs under the same exclusive service lock and never removes idempotency or receipt uniqueness tombstones.

The first release permits one active state-changing transaction per state root. A bounded in-memory queue may wait for that slot; overflow returns `503` with `Retry-After`. Health endpoints remain independent. A second process or concurrent process-level writer fails closed on the existing store lock.

Receipt-store capacity includes PASS, REVIEW, and BLOCKED receipts. Readiness becomes false at the configured safety threshold before exhaustion. Exhaustion fails closed. Store rotation is an offline operator procedure: activate a new store generation with a new audience/purpose or explicitly versioned store identity after old receipts expire, retain old idempotency and receipt tombstones read-only for their required audit period, and never merge or reset consumed state. Idempotency keys are scoped to the authenticated client and explicit store generation; a new generation is a deliberate protocol/configuration event, not automatic cleanup.

## 13. Outcome and HTTP behavior

- `PASS`: HTTP `200`; signed receipt; exact released bytes included.
- `REVIEW`: HTTP `200`; signed receipt; no released bytes.
- `BLOCKED`: HTTP `200`; signed receipt; no released bytes.
- malformed request or unsupported service protocol: HTTP `400`; no receipt; no released bytes.
- failed authentication or replayed auth nonce: HTTP `401`; no receipt; no released bytes.
- missing or inaccessible bundle: HTTP `422`; no receipt; no released bytes.
- idempotency digest conflict: HTTP `409`; no released bytes.
- request/body/resource limit: HTTP `413` or `422`; no released bytes.
- unavailable storage, signing, verifier exception, or internal failure: HTTP `503` or `500`; no released bytes.

CAGE must treat every non-200 response, malformed response, timeout, disconnect, invalid receipt, `REVIEW`, and `BLOCKED` as not admitted.

## 14. Limits and denial-of-service controls

The service enforces configured hard limits before allocation or processing:

- request-body bytes;
- envelope bytes;
- response UTF-8 bytes;
- sources per envelope;
- bytes per source;
- total source bytes;
- decisions, evidence items, claims, sections, and findings;
- header sizes and count;
- concurrent requests;
- request-read, queue-wait, and pure-verification-worker duration;
- receipt lifetime;
- stored idempotency records.

Request bodies are streamed with caps. Request-read and queue-wait deadlines end before a state-changing transaction begins. Pure verification runs in a worker that has no receipt or request-state mutation authority and may be terminated at its deadline.

After phase `verified`, receipt issuance, consumption, and result publication are not reported as cancelled. They run to a durable terminal or recoverable phase even if the HTTP client disconnects or its wait deadline expires. The client receives no bytes from the disconnected request and must make an authenticated idempotent retry. The service never reports that stateful work was aborted while it may continue in the background. It performs no automatic HTTP retries.

## 15. Logging and metrics

Logs may include:

- request ID;
- client ID;
- service and Agent Integrity protocol versions;
- status or service error code;
- finding codes only;
- receipt digest;
- response digest;
- duration;
- idempotent retry indicator.

Logs must not include:

- HMAC values or keys;
- signing keys;
- raw envelopes;
- response content;
- source content;
- policy or decision bytes;
- filesystem paths beyond configured logical bundle identifiers.

Metrics include request counts by outcome/error, authentication failures, replay attempts, idempotent retries/conflicts, latency, resource-limit rejections, and readiness state. Metrics do not label raw customer or source identifiers.

## 16. Key lifecycle

The sidecar loads one active Ed25519 private key from a protected file. Configuration supplies its key ID, issuer, audience, purpose, engine version, validity bounds, and the trusted public-key registry used by receipt recheck.

Startup fails if:

- the private key cannot be parsed;
- the active key is missing from the trusted registry;
- key metadata disagrees;
- the active key is revoked or outside its validity window;
- file permissions are broader than the configured policy permits.

Immediately before entering `receipt-prepared`, the sidecar captures a fresh host signing time and the current fully validated key registry. It checks that the active key ID is present, matches the configured public key and metadata, is not revoked, and is inside its validity interval at that fresh time. A key that expires or is revoked while pure verification is running therefore cannot authorize a new receipt preparation.

After `receipt-prepared` is durably published, its exact signing time, registry digest, key ID, and receipt inputs are frozen for crash recovery. This preparation is the admission point for receipt issuance: later configuration reloads do not rewrite it, and recovery may only reconstruct that exact receipt. Rotation procedures must retain the selected private key until no prepared transaction can remain recoverable. If the exact key material or matching registry snapshot is unavailable, recovery fails closed and readiness remains false; it does not select a replacement key. A receipt completed after later revocation may be rejected by CAGE's current trust registry, but the sidecar never releases bytes unless its own frozen receipt verification and consumption step succeeds.

Rotation uses an atomic configuration reload. The service fully parses and validates the new HMAC and receipt key registries before swapping the immutable snapshot used for new receipt preparations. Pure-verification requests that have not reached `receipt-prepared` use the new registry; already prepared transactions retain their frozen snapshot. Historical public receipt keys remain available for verification. CAGE must pin or retrieve the public trust registry through a separately authenticated deployment/configuration channel; it never trusts a key supplied by an individual sidecar response. Private key material is never written into receipts, logs, configuration examples, fixtures, or responses.

## 17. Shutdown and recovery

On `SIGTERM` or `SIGINT`, the service:

1. stops accepting new connections;
2. terminates cancellable pure-verification workers at their deadline;
3. waits up to the configured grace period for admitted state-changing transactions to reach a durable recoverable phase;
4. closes the socket;
5. exits non-zero if safe shutdown cannot be established.

If grace expires, the process exits after flushing the latest phase journal; startup recovery validates and advances only provable phases. Recovery operations for abandoned receipt-store locks, contradictory state, incomplete idempotency transactions, or staging files require an explicit offline-exclusive operator command. The server never steals locks automatically.

## 18. Test design

Required test classes:

### Functional outcomes

- valid fixture returns `PASS`, real signed receipt, and exact response bytes;
- ambiguous support returns `REVIEW`, signed receipt, and no response bytes;
- rejected decision returns `BLOCKED`, signed receipt, and no response bytes.

### Binding and mutation

- one-byte response mutation;
- source mutation after bundle publication;
- decision-registry mutation;
- policy mismatch;
- changed bundle ID;
- changed request after HMAC calculation;
- changed receipt or signature;
- exact response SHA-256 and base64 round trip.

### Authentication and replay

- missing, malformed, wrong-client, expired, and future-dated authentication;
- unknown, expired, and revoked HMAC key IDs;
- bad HMAC, non-canonical base64url, wrong length, and duplicate authentication headers;
- non-canonical JSON and duplicate JSON keys;
- authentication nonce replay;
- fresh authentication nonce plus the same idempotency key and exact body retry;
- same idempotency key with changed digest;
- same idempotency key after result expiry or full-record cleanup remains bound and cannot issue again;
- receipt consumption replay.

### Filesystem and bundle boundary

- absolute path, traversal, separator, symlink, and nested-path bundle IDs;
- missing manifest/source/policy/registry;
- incorrect manifest self-digest, duplicate paths, extra files, missing files, size/digest mismatch, hardlinks, and non-regular files;
- incoming root replacement and mutation during private-snapshot copying;
- source outside allowed roots;
- mutable or inconsistent snapshot;
- stale Unix socket, socket-path symlink, wrong owner/group/mode, and startup race;
- inaccessible or broadly permissioned secret/state/socket paths;
- separate `cage` and `agent-integrity` identity access and denial cases.

### Failure and crash windows

- receipt-store write and synchronization failures;
- crash after durable `receipt-prepared` but before signing begins;
- crash after store issuance but before `createReceipt()` returns, recovered from the exact prepared inputs without a second issuance;
- crash after receipt issuance but before receipt output completion;
- crash after receipt issuance but before `receipt-issued` phase publication;
- crash after PASS consumption but before `pass-consumed` or `result-committed` publication;
- idempotency reservation/completion failures;
- signing failure;
- verifier exception;
- pure-verification worker timeout proves no receipt or result mutation;
- client timeout/disconnect while state-changing work continues to a durable phase;
- client disconnect after durable completion;
- process restart followed by authenticated idempotent retry;
- completed-result retry succeeds without reopening an incoming bundle that has been removed;
- active signing-key expiry during pure verification prevents receipt preparation;
- active signing-key revocation during pure verification prevents receipt preparation;
- key rotation after durable preparation can only recover the exact frozen receipt and never selects the replacement key;
- atomic valid and invalid configuration reload;
- cross-process concurrent requests against one state root;
- nonce, idempotency, and receipt quota exhaustion;
- completed-result expiry, redelivery denial, and retention cleanup;
- graceful and forced shutdown.

### Limits and information disclosure

- oversized body and headers;
- excessive sources/claims/evidence/findings;
- timeout and concurrency rejection;
- bounded queue overflow and readiness degradation near store capacity;
- logs and errors contain no raw content, paths, or secrets;
- health responses reveal no sensitive metadata.

### Compatibility

- public envelope and receipt schemas remain byte-identical;
- existing CLI, SDK, core, and conformance tests remain green;
- clean install and package checks pass;
- no network call participates in verdict calculation.

## 19. Acceptance gates

The sidecar design is accepted for implementation only if:

- the service remains response/artifact verification, not action authorization;
- the public protocol schemas remain unchanged;
- the API returns release bytes only after authenticated receipt consumption;
- all trusted configuration is loaded outside the request;
- exact request authentication and idempotency bindings are defined;
- CAGE and the sidecar use separate Unix identities and CAGE cannot read the receipt-signing key;
- evidence is verified from a sidecar-owned private snapshot with an exhaustive manifest;
- receipt issuance, consumption, and result publication use a recoverable phase machine rather than an unsupported atomicity claim;
- only pure verification is cancellable; admitted state-changing work reaches a durable recoverable phase;
- signing-key validity and revocation are checked per request;
- result redelivery ends no later than receipt expiry;
- no broad filesystem or network authority is required;
- every technical failure releases nothing;
- local filesystem limitations and recovery procedures are explicit;
- the CAGE follow-up can consume the API without importing Node internals.

## 20. Follow-up boundary

After this sidecar passes its own implementation and security review, a separate CAGE design will cover:

- trusted envelope and evidence-snapshot construction;
- Unix-socket HTTP client authentication;
- response and receipt parsing;
- preservation of the complete signed receipt;
- release of only decoded `releasedResponse.bytes`;
- synchronous versus asynchronous enforcement classes;
- migration away from the mock production path;
- CAGE-specific operational and CI evidence.

That CAGE design may not change Agent Integrity verdict semantics or silently reinterpret the response envelope as action authorization.
