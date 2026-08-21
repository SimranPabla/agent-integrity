# Copilot Review Fixes Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve the three approved Copilot findings while preserving the existing tag-workflow identity check.

**Architecture:** Keep each fix local to its existing module. Provenance parsing remains pure, publish cleanup wraps the current script body, and receipt-store portability uses a small errno classifier.

**Tech Stack:** Node.js ESM, TypeScript, Vitest, GitHub Actions

---

## Chunk 1: Regression fixes

### Task 1: Bind provenance to the signed commit

**Files:**
- Modify: `tests/release/provenance.test.ts`
- Modify: `scripts/release-status.mjs`

- [ ] Add tests proving `digest.gitCommit` is extracted and absent/mismatched commits fail closed.
- [ ] Run the focused provenance tests and confirm the old implementation fails.
- [ ] Implement strict extraction from the matching repository in `resolvedDependencies`.
- [ ] Run the focused tests and confirm they pass.

### Task 2: Clean npm pack temporary files

**Files:**
- Modify: `scripts/publish-package.mjs`
- Create: `tests/release/publish-package.test.ts`

- [ ] Add a regression test that stubs npm commands and confirms cleanup after success and failure.
- [ ] Wrap pack/view/publish behavior in `try/finally` and recursively remove the destination.
- [ ] Run the focused test.

### Task 3: Handle unsupported Windows directory opens

**Files:**
- Modify: `packages/core/src/receipts/file-receipt-store.ts`
- Modify: `packages/core/tests/receipts/receipt.test.ts`

- [ ] Add tests for known unsupported open errors and unexpected errors.
- [ ] Ignore only `EPERM`, `EACCES`, and `EISDIR` from directory open; keep sync handling unchanged.
- [ ] Run receipt-store tests.

### Task 4: Verify and deliver

- [ ] Run the full verification suite.
- [ ] Review the diff for scope and secrets.
- [ ] Commit and push to `feat/public-release-governance`.
- [ ] Confirm CI and request a new Copilot review.
