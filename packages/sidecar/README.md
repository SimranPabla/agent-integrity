# Private Verified-Release Sidecar

## Status

This package is an implementation in progress. It is not yet a deployable service and the pull request must remain in draft until the remaining implementation tasks and final adversarial review are complete.

The current tree contains Tasks 1–9 of the approved plan in `docs/plans/private-verified-release-sidecar-implementation.md`. Task 8 is published; Task 9 has passed independent specification and scoped security re-reviews, with local checkpoint/final acceptance recorded separately. This does not authorize deployment or publication of Task 9.

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

- Private archive admission with path, link, entry-count, and byte ceilings.
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
- Production resolves the compiled sibling `verification-worker.js`. Vitest source execution uses the existing Vite development dependency to evaluate current TypeScript and relative imports in the thread; it never falls back to stale sidecar `dist` files. Source execution outside Vitest is rejected. Worker stdout/stderr are drained without disclosure.

Worker threads provide **cooperative cancellation/isolation, not an operating-system sandbox for hostile code**. They retain the process Unix identity and ambient filesystem privileges. Trusted parent code selects snapshot roots and limits; the model does not. Protected snapshot ownership and the single trusted mutation coordinator remain necessary.

The private snapshot manifest does not retain the original request envelope digest. This layer binds policy/source/decision data to the current envelope; Task 8 durably binds the selected snapshot identity and exact envelope/request digest in the transaction. Task 9 assembles the bounded queue, runtime, transport and protected offline recovery around that transaction.

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

## Remaining implementation

Task 8 supplies durable verified-release/recovery orchestration; Task 9 adds Unix-socket transport, runtime, health and protected recovery CLI. Remaining approved-plan work includes Task 10 integration/identity/network/clean-install and joint CAGE fixtures, and Task 11 deployment/operations/final adversarial acceptance. No production service has been deployed. Operator instructions for this local slice are separate from deployment approval.

Until these are complete, this package must not be represented as a finished sidecar or production control plane.

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
