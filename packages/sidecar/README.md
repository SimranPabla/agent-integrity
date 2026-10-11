# Private Verified-Release Sidecar

## Status

Local tested-code checkpoint `b8523dae9ff613dca6a2c9316774d76f75dd072f` passed qualified Task 10 implementation reviews and two independently checked full runs (each 978 passed, 2 skipped, 80 files). **runtimeReady: false**: actual Linux UID/GID and network-namespace scripts returned 77 (INCONCLUSIVE); Node 22 was unavailable. Node 24.21.0/npm 12.0.2 were exercised October 10, 2026. Task 11 final independent reviews, deployment qualification and separate CAGE runtime integration remain outstanding. See [executed evidence](../../docs/results/2026-09-18-private-sidecar-result.md).

The package `@agent-integrity/sidecar` remains `private: true`. The exact public npm set is `@agent-integrity/protocol`, `@agent-integrity/core`, `@agent-integrity/sdk`, and `@agent-integrity/cli`; the sidecar is compiled and smoke-checked separately, never packed publicly.

## Implemented components

### 1. Closed service protocol

- Canonical, size-bounded request and response parsing.
- Exact request and response schemas with unknown-field rejection.
- Stable technical error responses and explicit PASS, REVIEW, BLOCKED, and RELEASE_REFUSED outcomes.
- Response-to-request and signed-receipt binding checks.

### 2. Authentication and replay protection

- Exact HMAC request authentication over the admitted canonical bytes.
- Bounded clock-skew and authentication-key overlap handling.
- Durable, create-once nonce reservation with strict private permissions.
- Fail-closed replay, malformed-state, capacity, and durability behavior.

### 3. Evidence-bundle admission

- Private directory-bundle admission with path, link, entry-count, and byte ceilings; no archive parser.
- Exact source snapshotting and content-addressed object identities.
- Bundle expiry and clock-skew enforcement.
- Canonical manifest validation and fail-closed source mutation detection.

### 4. Deterministic receipt recovery

- Caller-supplied transaction identities for recoverable receipt issuance.
- Deterministic prepared receipt material and recovery inspection.
- Durable transaction, quota, issued, consumed, closed, and cleanup records.
- Strict rollback and reconciliation behavior for partial failures.

### 5. Durable request orchestration

- Closed, versioned request phases from reservation through terminal result or tombstone.
- Branch-specific transition enforcement for PASS and non-PASS outcomes.
- Exact canonical request bytes stored content-addressed before reservation publication.
- Idempotency scoped by client and store generation, with exact retry, digest-conflict rejection, and permanent tombstones after expiry.
- One state-root lease and a live, unforgeable mutation capability.
- Cross-process lease exclusion plus exact-token offline recovery through an append-only, complete-inventory ownership handoff.
- Receipt-store nested locks bound to the coordinator owner token, store generation, and root identity; stale capabilities cannot mutate the receipt store.
- Bounded record capacity, strict state permissions, create-once publication, directory durability, and reference-aware request-object cleanup.

### 6. Configuration, Unix identities, and key lifecycle

- Explicit absolute configuration file only; closed nested fields, fixed state children, explicit store generation, bounded limits, and deeply frozen secret-redacted snapshots.
- Exact Unix identity/group, file type/mode/link, canonical path/ancestor, root-owned socket-parent, and protected-file identity checks. Stat, path resolution, and process identity readers are injectable for non-root tests; production defaults use the host OS.
- Owner-only readable configuration permits `0400` or `0600`; group/other access and special bits are forbidden. Secrets remain exact `0400`.
- Client-group membership is resolved from both primary passwd GIDs and supplementary group member names using NSS, not `/etc` files. Production requires trusted `/usr/bin/getent` and complete enumerable NSS passwd/group databases. Each fixed, shell-free query has a 5-second timeout, 4 MiB output bound, and 65,536-record ceiling. Enumeration errors, malformed/ambiguous records, unresolved names, missing groups, and any set other than the two distinct configured CAGE/sidecar UIDs fail closed. Non-enumerating NSS backends are unsupported; operators must establish complete enumeration rather than treating a partial NSS view as proof. Membership is checked on every load/reload; the host administrator remains trusted against account-database changes between checks. The group resolver is injectable for non-root tests.
- Whole-candidate validation before atomic HMAC/receipt registry replacement; failed or concurrent reloads cannot replace the active snapshot. Deployment identities, roots, and store generation cannot change online. A complete unsigned-manifest digest shared with the exporter/parser enforces a strictly increased generation for signed-content changes (and authority public-key rebinding); identical manifests and nonmanifest-only changes may retain the generation.
- Sorted historical public receipt keys remain available; key IDs cannot be rebound. Active signing keys are checked against an injected fresh clock; expired/revoked active keys fail closed. Referenced recovery private keys remain available by key ID until their retain handles are released.
- Separately signed, public-only canonical CAGE JWKS export for the out-of-band configuration channel. No network endpoint is added.

The JWKS contains exact public Ed25519 JWK members `kty`, `crv`, `x`, `kid`, `use`, and `alg`. All lifecycle controls reside in the single `https://github.com/SimranPabla/agent-integrity/params/jwks/receipt-manifest/v1` extension. Its digest covers the complete canonical set with only `manifestDigest` and `signature` omitted. The pinned authority signs UTF-8 `cage-agent-integrity-trust-manifest-v1`, one NUL byte, and the raw 32-byte digest. Public keys and signatures use canonical unpadded base64url (32 and 64 decoded bytes).

Generic JWKS parsing is compatible but is **not** sufficient admission authority. The closed parser additionally validates sorted one-to-one key metadata, profile ceilings, signature, fresh time, and the accepted generation/digest pair. Task 8 durably binds prepared transactions and registry snapshots; operators must keep required original configured key files across restarts until durable prepared transactions are resolved. Joint CAGE integration and deployment qualification remain later tasks.

### 7. Cancellable trusted verification

- A closed, recursively frozen worker message carries only canonical envelope bytes, private snapshot root/identity, and explicit host byte/item limits. Store handles, mutation capabilities, keys and callbacks are not accepted.
- The worker reopens the content-addressed private snapshot with exhaustive identity/file validation. Only its manifest-bound project files supply independently parsed trusted policy and configuration. Configuration requires exactly `allowedRoots`, `decisionRegistryPath`, `maxSourceBytes` and `maxTotalSourceBytes`; the historical CLI-style `projectRoot` field and omitted/default limits are rejected.
- Policy roots, decision path/digest and source membership/size/digests are bound to the manifest and current envelope. Host ceilings apply before trusted verification; the returned context is recursively frozen.
- The parent checks canonical, closed, envelope-digest-bound verification output, finding counts/bytes and calculated verdict consistency. Worker failures, malformed output, timeout and abort return metadata-only technical failure, with termination awaited before return. No receipt issuance or request-state mutation is performed.
- Bound trusted policy/config/decision reads use `O_NOFOLLOW | O_NONBLOCK`, then require a regular private file before reading. A FIFO substituted after snapshot admission is rejected without waiting for a writer; this is a bounded reopen check, not protection against a hostile trusted host.
- Production resolves the compiled sibling `verification-worker.js`. Vitest source execution uses a worker-local Node loader with native TypeScript transformation when available and a TypeScript compiler fallback for current source and relative imports; it never falls back to stale sidecar `dist` files. Source execution outside Vitest is rejected. Worker stdout/stderr are drained without disclosure.

Worker threads provide **cooperative cancellation/isolation, not an operating-system sandbox for hostile code**. They retain the process Unix identity and ambient filesystem privileges. Trusted parent code selects snapshot roots and limits; the model does not. Protected snapshot ownership and the single trusted mutation coordinator remain necessary.

The version-2 private snapshot retains `originalManifest.envelopeDigest` and validates it against `expectedRequest`. This layer binds policy/source/decision data to the current envelope; Task 8 durably binds the selected snapshot identity and exact envelope/request digest in the transaction. Task 9 assembles the bounded queue, runtime, transport and protected offline recovery around that transaction.

## Security guarantees established so far

- State is rejected when it is malformed, oversized, ambiguously branched, unexpectedly replaced, or published with conflicting ownership.
- No request-state mutation is accepted without the active coordinator capability.
- A second coordinator cannot steal an existing state-root lease.
- Partial, mismatched, disconnected, or cyclic ownership handoffs fail closed.
- Idempotency keys cannot be reused with changed request bytes or after tombstone compaction.
- Request objects are digest-checked on publication and every read.
- Receipt-store locks in sidecar mode cannot mint an independent owner token.

These are implementation and test guarantees only. They do not establish production readiness or approve deployment.

## Verification

Focused configuration/key lifecycle verification:

```bash
npm run typecheck
npx vitest run packages/sidecar/tests/config.test.ts packages/sidecar/tests/permissions.test.ts packages/sidecar/tests/client-group.test.ts packages/sidecar/tests/cage-trust-manifest.test.ts
```

Automated Task 7 regression coverage (also included in plain `npm test`):

```bash
npx vitest run packages/sidecar/tests/verification-runner.test.ts packages/sidecar/tests/trusted-context.test.ts packages/sidecar/tests/trusted-context-fifo.test.ts packages/sidecar/tests/verification-compiled.test.ts
```

The compiled regression invokes the installed TypeScript compiler once into an invocation-unique ignored `dist/task7-smoke-*` tree. It compiles current worker/runner sources and reachable relative dependencies without incremental state, project-reference builds, or writes to package `dist` trees. A plain child Node process (without `VITEST` or Vite) runs PASS/REVIEW/BLOCKED with a parent-only `--input-type=module` flag, then checks missing and sentinel sibling JS failures. Only its own scratch tree and fixtures are removed. Workspace dependency packages must have their normal compiled artifacts, as required by the existing repository test setup; the sidecar worker never uses shared/stale sidecar output. The FIFO regression requires the Unix `mkfifo` utility and includes a bounded rescue writer so a blocking-open regression fails rather than hanging the process.

Repository verification:

```bash
npm run verify
npm run release:check
npm run pack:check
```

GitHub Actions independently runs the required Node 22 and Node 24/npm 12 jobs for every published pull-request head.

## Acceptance still required

Final independent Task 11 specification/security reviews and owner review remain pending. Real separate-user and no-network execution requires a suitably privileged Linux environment. Joint partner fixtures and Provider 06 runtime integration require a separate CAGE PR against its current layout. No local check authorizes deployment.

## Task 9 local command surface (local-only; not deployment approval)

This private workspace package is excluded from the public npm publish set. It uses Node built-ins and HTTP over one Unix domain socket; no TCP listener. Local tests are not production-readiness or separate-identity proof.

```text
integrity-sidecar check-config --config /absolute/path/config.json
integrity-sidecar serve --config /absolute/path/config.json
integrity-sidecar recover --config /absolute/path/config.json --offline-exclusive --authorization-file /absolute/path/recovery.json
```

Configuration and keys are protected files, never argv secrets. Commands emit redacted JSON codes. Configuration check does not acquire state authority or bind a socket. SIGTERM/SIGINT stop admission, cancel only pure verification and drain durable work; an unsafe drain exits nonzero and preserves authority.

Offline recovery requires stopping every writer first. `--offline-exclusive` is an operator assertion, **not OS proof of process death**. Recovery rejects a live configured socket and requires an exact canonical 0400 authorization outside incoming/state roots, owned by root or the sidecar identity, with version 1, action recover, storeGeneration, rootIdentityDigest, abandonedOwnerToken, issuedAt, expiresAt and unique nonce. Never delete locks or reset replay/consumption records. The immutable authorization derives the next owner; the complete handoff is durable before a create-once consumed audit, and the audit precedes source removal. A consumed authorization is not reusable. Failures preserve recoverable state and may require a new separately authorized offline operation; there is no automatic lock stealing.

OS provisioning, system services, real separate-user/no-network proof and deployment are outside this package slice.

Shutdown validates the pinned socket and directory immediately before closing the Node listener, then stops accepting new connections while durable work drains. Forced grace expiry preserves the root lease and returns unsafe. Node/libuv itself unlinks the bound pathname when closing its listener; portable JavaScript cannot promise preservation against a same-identity hostile replacement in the final validation-to-close race. Pre-existing detected substitutions fail closed before listener close. This limitation is not separate-user isolation proof.

Readiness observes fresh lease and initialized store capacity without queue admission, new receipt-store locks, issuance or consumption. Concurrent or malformed state observations fail closed; healthy busy operation is not inferred from cached readiness. Authorization replay preflight is read-only; audit initialization/publication runs only with the exact live root recovery capability.

## Exact guarantee and verdict routing

Under the trusted-host assumptions below, successful authenticated processing snapshots admitted evidence, verifies the exact envelope against that snapshot, signs a real receipt, durably consumes PASS, and commits the canonical result before delivery. Returned base64 decodes to the exact UTF-8 envelope response content; SHA-256 binds it. This is recoverable local single consumption and bounded idempotent redelivery, not distributed exactly-once downstream delivery. Dispatch the returned buffer itself, never a reconstruction.

- PASS: wrapper and signed receipt verification canonically equal PASS; only this outcome has releasedResponse.
- REVIEW/BLOCKED: matching signed verification/receipt, no response bytes; preserve refusal evidence and hold/stop.
- RELEASE_REFUSED: signed prospective PASS receipt, terminal release.status REVIEW/BLOCKED, code RECEIPT_RECHECK_REFUSED, retryable false, no bytes. Preserve receipt and refusal; the receipt alone is not release authority.
- Technical failure: closed protocol version/optional safely parsed request ID/error metadata only. Never infer rollback of nonce, reservation, prepared, issued, consumed or closed state.

The durable phase graph is reserved → verified → receipt-prepared → receipt-issued. PASS proceeds through pass-consumed → result-committed; release refusal through release-refused → result-committed; REVIEW/BLOCKED commit without consumption. Expired completed results compact to permanent tombstones. Recovery follows the original legal branch, signing/trust/request bindings, never replacement identities to evade consumption.

Retries need the same client, store generation, idempotency key and exact canonical request digest, but a fresh authentication nonce. Completed retries return byte-identical canonical responses only within their delivery deadline. Changed bodies conflict; expired/tombstoned requests do not release bytes. Disconnect/output-write failure never authorizes undoing durable issuance or consumption.

## Provisioning and operating criteria

These are operator requirements, not exercised deployment commands. Use distinct non-root CAGE and sidecar UIDs. The client group must enumerate exactly those two UIDs through complete NSS primary/supplementary membership. No unrelated memberships, shared signing-key access, ambient root, CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH or CAP_FOWNER. The implementation does not create users, drop capabilities, enforce a network namespace or sandbox hostile same-identity code; privileged administrators and account changes between checks remain trusted-host assumptions.

Socket directory: sidecar UID/client GID, 0710, beneath a canonical root-owned parent without group/other write; socket 0660, pathname at most 103 UTF-8 bytes. Private state/snapshot directories 0700, durable records 0600. Configuration is a regular owner-only 0400 or 0600 file. HMAC, receipt-signing and manifest-authority private-key files are regular 0400 files, never inline values or argv secrets. HMAC material is 32–1024 raw bytes; Ed25519 private files must parse through Node createPrivateKey and match the configured raw public registry/authority. Provision separate protected HMAC copies for CAGE and sidecar; CAGE-copy isolation is the operator's responsibility. Ancestor/link/identity checks fail closed, not against a hostile trusted host.

CAGE owns closed incoming bundle publication and completeness; sidecar copies admitted content into a private content-addressed snapshot. The configured incoming root is CAGE UID/client GID, 0750. Incoming contents must be stable and protected beneath it. Links, traversal, malformed manifests, mutation and expiry fail closed. Bundle lifetime ≤900,000 ms, timestamp skew ≤60,000 ms. Durable request/snapshot identity persists through recovery even after incoming deletion. Never remove objects referenced by unresolved transactions.

HMAC overlap is bounded by configuration (≤86,400 seconds). Nonce uniqueness excludes key ID; rotation cannot reuse a nonce. Receipt rotation retains sorted historical public keys without kid rebinding and original private-key files required by prepared transactions across restarts. Revoked/expired active keys fail closed at fresh time. Reload validates the whole candidate atomically; failed/concurrent candidates cannot partially replace active registries. No signal-based reload command is promised. The shipped serve path captures its configuration and HMAC service snapshot at construction; manager-level reload tests do not establish a CLI live-rotation control. Operator rotation therefore requires a safely drained stop, complete reviewed candidate/config/key provisioning, and restart, preserving all original files needed by recovery. Signed manifest changes require a strictly greater manifest generation; that is distinct from state storeGeneration, which cannot change online. Never reset nonce, consumption, quota, handoff or request tombstones. New-store migration needs independent review, new generation and audience/purpose separation.

GET /health/live and GET /health/ready run over UDS without queue admission. Liveness is not authorization. Readiness freshly observes lease, keys and initialized store capacity without issuance, consumption or new receipt-store locks; stale/malformed/concurrent observations fail closed. One outstanding probe per prerequisite, default 1,000 ms timeout, hard 5,000 ms maximum, at most 64 codes. Late results cannot become healthy after timeout/shutdown. Busy health is not inferred from cached readiness.

Production runtime fixes headers at 8 KiB/64 fields, connections at 16, read timeout 10,000 ms, queue maximum 8 with 5,000 ms admission timeout and pure verification timeout 5,000 ms. General independent transport ceilings: headers 64 KiB/128 fields, connections 128, envelope items/findings 10,000; configured request/envelope/source/aggregate bytes, read time and queue/worker capacity must remain bounded. Exact released bytes ≤16 MiB; canonical wrapper/base64/signed receipt ≤32 MiB. Trusted configuration requires explicit coherent limits, no omitted defaults. Capacity exhaustion fails closed; permanent tombstones consume capacity. Monitor and migrate before exhaustion, never delete uniqueness records.

Minimum assumptions: trusted administrator and fresh clock, complete enumerable NSS, protected single-host local filesystem with hard-link publication and supported durability semantics, no hostile sidecar-identity writer, one live mutation owner, trusted out-of-band keys and CAGE evidence. Offline exclusivity is an operator assertion, not PID/process-death proof. SIGKILL tests do not prove power-loss survival, hardware durability, OS isolation, network denial, semantic truth, completeness, production SLA or CAGE admission. Back up complete state plus required original config/keys only while every writer is stopped or via an approved consistent snapshot; never restore older replay state over a newer live store.

Keep an operator-local runbook selected through SIDECAR_RUNBOOK_PATH, never commit host identities or secrets. Run the secret scanner with that readable external path and scoped ripgrep. Exit 0: no detected material; 1: material found; 2: scanner/tool/read failure. Pattern scanning is not general secret-detection proof; committed JSON/YAML fixture structures are checked separately.

### Client wire and operational output

POST /v1/verify-release uses application/json and exact RFC8785 canonical body bytes: serviceProtocolVersion, requestId, idempotencyKey, bundleId, envelope, with unknown/duplicate fields rejected. Exactly one of each authentication header is required: x-agent-integrity-client, x-agent-integrity-key-id, x-agent-integrity-timestamp, x-agent-integrity-nonce, x-agent-integrity-signature. HMAC-SHA256 signs the ASCII agent-integrity-sidecar-auth-v1 prefix plus eight UTF-8 fields, each preceded by its four-byte big-endian length: method, path, protocol version, client ID, key ID, timestamp, nonce and admitted canonical body SHA256. MAC is canonical unpadded base64url. Pure bounded parsing precedes MAC verification; only successful MAC enters the mutation coordinator and consumes a durable nonce.

CLI successful redacted codes are CONFIGURATION_VALID, SERVICE_STARTED, SERVICE_STOPPED and RECOVERY_COMPLETE. COMMAND_FAILED, RECOVERY_REQUIRED and SHUTDOWN_UNSAFE are not readiness; unsafe shutdown exits nonzero and preserves authority. No stdout receipt/key disclosure or TCP endpoint is provided. Offline authorization is consumed after immutable root handoff and before nested continuation; a failure after consumption requires a new authorization, not replay of the old one.
