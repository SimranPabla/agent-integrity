# Public Agent Integrity V1 Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a clean, local-first TypeScript integrity engine that independently verifies agent responses against approved evidence and decisions.

**Architecture:** A language-neutral protocol package feeds a deterministic core package; an SDK constructs complete envelopes and enforces exact-response release, while a CLI provides JSON stdin/stdout interoperability. Human policy is strict YAML, but all run artifacts and hashing use canonical JSON.

**Tech Stack:** Node.js 22+, TypeScript, Vitest, AJV, YAML parser with strict schema, npm workspaces

---

## Chunk 1: Foundation and deterministic primitives

### Task 1: Repository and public boundary

**Files:**
- Create: `package.json`
- Create: `tsconfig.base.json`
- Create: `.gitignore`
- Create: `README.md`
- Create: `docs/THREAT_MODEL.md`
- Create: `docs/PUBLIC_PRIVATE_BOUNDARY.md`

- [ ] Initialize a separate Git repository with no remote.
- [ ] Add workspace scripts for build, typecheck, and test.
- [ ] Document what the engine proves and explicitly does not prove.
- [ ] Document prohibited private inputs and run a secret scan before release.
- [ ] Run `npm install` and commit only the foundation files.

### Task 2: Stable protocol primitives

**Files:**
- Create: `packages/protocol/package.json`
- Create: `packages/protocol/tsconfig.json`
- Create: `packages/protocol/src/types.ts`
- Create: `packages/protocol/src/index.ts`
- Test: `packages/protocol/tests/types.test.ts`

- [ ] Write failing compile/runtime tests for protocol status and finding types.
- [ ] Run the narrow test and confirm failure.
- [ ] Implement versioned envelope, claim, evidence, decision, finding, result,
  and receipt types without ARC-specific fields.
- [ ] Run the narrow test and confirm pass.
- [ ] Commit the protocol slice.

### Task 3: Canonical JSON and hashing

**Files:**
- Create: `packages/core/package.json`
- Create: `packages/core/tsconfig.json`
- Create: `packages/core/src/canonical-json.ts`
- Create: `packages/core/src/hash.ts`
- Create: `packages/core/src/index.ts`
- Test: `packages/core/tests/canonical-json.test.ts`

- [ ] Write failing tests for key ordering, arrays, Unicode, invalid numbers,
  undefined values, and equivalent-object hash stability.
- [ ] Run the test and confirm failure.
- [ ] Implement deterministic canonical serialization and SHA-256 hashing.
- [ ] Run the test and confirm pass.
- [ ] Commit the deterministic primitive slice.

### Task 4: Outcome calculation

**Files:**
- Create: `packages/core/src/outcome.ts`
- Test: `packages/core/tests/outcome.test.ts`

- [ ] Write failing tests proving `BLOCKED` outranks `REVIEW`, `REVIEW`
  outranks `PASS`, and checker errors fail closed.
- [ ] Run the test and confirm failure.
- [ ] Implement the minimal deterministic reducer.
- [ ] Run all Chunk 1 tests and typecheck.
- [ ] Commit the outcome slice.

## Chunk 2: Policy, sources, and decisions

### Task 5: Strict one-time YAML policy

**Files:**
- Create: `packages/core/src/policy/parse-policy.ts`
- Create: `packages/protocol/src/policy.ts`
- Test: `packages/core/tests/policy/parse-policy.test.ts`

- [ ] Add fixtures and failing tests for valid policy plus duplicate keys,
  aliases, tags, ambiguous booleans/dates, and unknown fields.
- [ ] Implement strict parse-to-canonical-JSON behavior.
- [ ] Run tests and commit.

### Task 6: Trusted source collection

**Files:**
- Create: `packages/core/src/sources/collect-source.ts`
- Create: `packages/core/src/sources/path-boundary.ts`
- Test: `packages/core/tests/sources/source-integrity.test.ts`
- Test: `packages/core/tests/adversarial/path-boundary.test.ts`

- [ ] Write failing tests for exact-byte hashing, traversal, absolute paths,
  symlink escape, mutation, encoding, and line-ending differences.
- [ ] Implement realpath-based allowed-root enforcement and byte hashing.
- [ ] Run tests and commit.

### Task 7: Decision lifecycle

**Files:**
- Create: `packages/core/src/decisions/reduce-decisions.ts`
- Test: `packages/core/tests/decisions/reduce-decisions.test.ts`
- Test: `packages/core/tests/adversarial/decision-revival.test.ts`

- [ ] Write failing tests for active, rejected, superseded, duplicate, and
  conflicting decision events.
- [ ] Implement deterministic lifecycle reduction.
- [ ] Run tests and commit.

## Chunk 3: Claims, verification, and receipts

### Task 8: Claim coverage and evidence roles

**Files:**
- Create: `packages/core/src/claims/coverage.ts`
- Create: `packages/core/src/claims/evidence.ts`
- Test: `packages/core/tests/claims/coverage.test.ts`
- Test: `packages/core/tests/adversarial/hidden-contradiction.test.ts`

- [x] Write failing tests for uncovered substantive sections, missing support,
  contextual-only evidence, and undisclosed contradictions.
- [x] Implement deterministic structural checks; semantic ambiguity emits
  review findings rather than blocking.
- [x] Run tests and commit.

### Task 9: Complete-envelope verification

**Files:**
- Create: `packages/core/src/verify.ts`
- Test: `packages/core/tests/verification/verify.test.ts`
- Test: `packages/core/tests/adversarial/checker-failure.test.ts`

- [ ] Write failing end-to-end tests for pass, review, block, malformed input,
  and internal failure.
- [ ] Compose policy, source, decision, claim, and outcome checks.
- [ ] Bind the complete canonical envelope to the result.
- [ ] Run tests and commit.

### Task 10: Receipt creation and recheck

**Files:**
- Create: `packages/core/src/receipts/create-receipt.ts`
- Create: `packages/core/src/receipts/recheck-receipt.ts`
- Test: `packages/core/tests/receipts/receipt.test.ts`
- Test: `packages/core/tests/adversarial/replay.test.ts`

- [ ] Write failing tests for response/source mutation, expiry, duplicate run
  identifiers, overwrite refusal, and post-check editing.
- [ ] Implement alpha receipt persistence with explicit unsigned status.
- [ ] Implement recheck against live bound subjects.
- [ ] Run tests and commit.

## Chunk 4: Agent SDK, CLI, and release candidate

### Task 11: Agent SDK and release guard

**Files:**
- Create: `packages/sdk/package.json`
- Create: `packages/sdk/src/session.ts`
- Create: `packages/sdk/src/release.ts`
- Test: `packages/sdk/tests/session.test.ts`
- Test: `packages/sdk/tests/release.test.ts`

- [ ] Write failing tests for automatic envelope construction and exact-response
  release on pass only.
- [ ] Implement the minimal agent-facing API.
- [ ] Ensure review, block, mutation, and checker error release nothing.
- [ ] Run tests and commit.

### Task 12: CLI

**Files:**
- Create: `packages/cli/package.json`
- Create: `packages/cli/src/cli.ts`
- Test: `packages/cli/tests/cli.test.ts`

- [ ] Write failing tests for `validate-policy`, `verify`, `recheck`, and
  `inspect-receipt` using JSON stdin/stdout.
- [ ] Implement commands with stable exit codes and no sensitive source output.
- [ ] Run tests and commit.

### Task 13: Examples, conformance, and security docs

**Files:**
- Create: `examples/basic-agent/`
- Create: `examples/contradictory-evidence/`
- Create: `examples/superseded-decision/`
- Create: `examples/tampered-response/`
- Create: `tests/conformance/`
- Create: `SECURITY.md`
- Create: `CONTRIBUTING.md`
- Create: `LICENSE`

- [ ] Add runnable synthetic examples without ARC data.
- [ ] Publish a language-neutral conformance fixture set.
- [ ] Add threat-model, limitation, contribution, and vulnerability-reporting docs.
- [ ] Run typecheck, all tests, build, dependency audit, and secret scan.
- [ ] Add a plain-language offline operational runbook.
- [ ] Present the private staging release candidate for explicit approval before
  creating any public remote or publishing a package.
