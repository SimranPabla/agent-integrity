# Private Verified-Release Sidecar

## Status

This package is an implementation in progress. It is not yet a deployable service and the pull request must remain in draft until the remaining implementation tasks and final adversarial review are complete.

The current tree implements Tasks 1–7 of the approved plan in `docs/plans/private-verified-release-sidecar-implementation.md`.

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

Generic JWKS parsing is compatible but is **not** sufficient admission authority. The closed parser additionally validates sorted one-to-one key metadata, profile ceilings, signature, fresh time, and the accepted generation/digest pair. Persisting that pair, preparing transactions, publishing registry snapshots, and wiring recovery-key references into transactions remain later-task integration work. Recovery retain handles currently protect keys in process memory only; operators must keep the configured key files across restarts until durable prepared transactions are resolved.

### 7. Cancellable trusted verification

- A closed, recursively frozen worker message carries only canonical envelope bytes, private snapshot root/identity, and explicit host byte/item limits. Store handles, mutation capabilities, keys and callbacks are not accepted.
- The worker reopens the content-addressed private snapshot with exhaustive identity/file validation. Only its manifest-bound project files supply independently parsed trusted policy and configuration. Configuration requires exactly `allowedRoots`, `decisionRegistryPath`, `maxSourceBytes` and `maxTotalSourceBytes`; the historical CLI-style `projectRoot` field and omitted/default limits are rejected.
- Policy roots, decision path/digest and source membership/size/digests are bound to the manifest and current envelope. Host ceilings apply before trusted verification; the returned context is recursively frozen.
- The parent checks canonical, closed, envelope-digest-bound verification output, finding counts/bytes and calculated verdict consistency. Worker failures, malformed output, timeout and abort return metadata-only technical failure, with termination awaited before return. No receipt issuance or request-state mutation is performed.
- Bound trusted policy/config/decision reads use `O_NOFOLLOW | O_NONBLOCK`, then require a regular private file before reading. A FIFO substituted after snapshot admission is rejected without waiting for a writer; this is a bounded reopen check, not protection against a hostile trusted host.
- Production resolves the compiled sibling `verification-worker.js`. Vitest source execution uses the existing Vite development dependency to evaluate current TypeScript and relative imports in the thread; it never falls back to stale sidecar `dist` files. Source execution outside Vitest is rejected. Worker stdout/stderr are drained without disclosure.

Worker threads provide **cooperative cancellation/isolation, not an operating-system sandbox for hostile code**. They retain the process Unix identity and ambient filesystem privileges. Trusted parent code selects snapshot roots and limits; the model does not. Protected snapshot ownership and the single trusted mutation coordinator remain necessary.

The private snapshot manifest does not retain the original request envelope digest. This layer binds policy/source/decision data to the current envelope; Task 8 must durably bind the selected snapshot identity and exact envelope/request digest in the transaction. Signing, consumption, recovery, queue integration and release remain Task 8/later work.

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

The following approved-plan areas are not yet implemented:

- trusted verification integration into the durable service transaction;
- Unix-socket service runtime, bounded transaction queue, and delivery recovery;
- release-output boundary integration and complete crash reconciliation;
- deployment assets, operator runbook, integration fixtures, and final adversarial test matrix.

Until these are complete, this package must not be represented as a finished sidecar or production control plane.
