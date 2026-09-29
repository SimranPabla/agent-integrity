# Private Verified-Release Sidecar

## Status

This package is an implementation in progress. It is not yet a deployable service and the pull request must remain in draft until the remaining implementation tasks and final adversarial review are complete.

The current tree implements Tasks 1–5 of the approved plan in `docs/plans/private-verified-release-sidecar-implementation.md`.

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

Focused Task 5 verification:

```bash
npm run typecheck
npx vitest run packages/sidecar/tests/request-store.test.ts
```

Repository verification:

```bash
npm run verify
npm run release:check
npm run pack:check
```

GitHub Actions independently runs the required Node 22 and Node 24/npm 12 jobs for every published pull-request head.

## Remaining implementation

The following approved-plan areas are not yet implemented:

- closed runtime configuration, permission checks, and signing-key lifecycle;
- CAGE JWKS trust-manifest export and reload behavior;
- exact CAGE subprocess supervision and trusted verification orchestration;
- Unix-socket service runtime, bounded transaction queue, and delivery recovery;
- release-output boundary integration and complete crash reconciliation;
- deployment assets, operator runbook, integration fixtures, and final adversarial test matrix.

Until these are complete, this package must not be represented as a finished sidecar or production control plane.
