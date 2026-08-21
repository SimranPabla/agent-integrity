# Public Release Governance Implementation Plan

> **For agentic workers:** Execute locally and test-first. Publication remains outside this plan.

**Goal:** Add exact-head pull-request proof and a fail-closed public release-status verifier before Agent Integrity becomes public.

**Architecture:** GitHub PR CI runs the same deterministic verification and package gates used by release. A standalone Node.js verifier accepts an explicit release manifest, queries GitHub and npm through injectable provider clients, and returns `CURRENT` only when the immutable tag, protected-main ancestry, successful release workflow, environment approval, npm provenance, versions, and tarball integrity all agree.

**Tech Stack:** GitHub Actions, Node.js 22, TypeScript/JavaScript, Vitest, GitHub REST API, npm registry API.

---

## Chunk 1: Exact-head pull-request proof

### Task 1: Shared CI gate

**Files:**
- Create: `.github/workflows/ci.yml`
- Modify: `.github/workflows/npm-release.yml`
- Test: `tests/release/workflows.test.ts`

- [ ] Test that PR CI is SHA-pinned, read-only, and runs install, audit, verify, release scan, and package checks.
- [ ] Add PR/push CI with a stable required-check job name.
- [ ] Test that release checks tag ancestry against `origin/main` before publication.
- [ ] Add full-history checkout and ancestry validation to release.

## Chunk 2: Canonical public release status

### Task 2: Pure verification core

**Files:**
- Create: `scripts/release-status-core.mjs`
- Test: `tests/release/release-status.test.ts`

- [ ] Define a strict manifest and normalized evidence model.
- [ ] Test the all-current path.
- [ ] Test tag, ancestry, workflow, approval, provenance, version, and integrity failures.
- [ ] Implement fail-closed deterministic status calculation.

### Task 3: Provider collector and CLI

**Files:**
- Create: `scripts/release-status.mjs`
- Create: `docs/release-status-manifest.example.json`
- Modify: `package.json`
- Test: `tests/release/release-status-cli.test.ts`

- [ ] Test CLI input, redacted output, exit codes, pagination, and provider failures.
- [ ] Implement GitHub and npm collection with explicit timeouts and pagination.
- [ ] Verify tag commit, main ancestry, exact release workflow run, protected environment reviewer, npm provenance, versions, and registry integrity.

## Chunk 3: Operations and closure

### Task 4: Documentation and offline runbook

**Files:**
- Modify: `docs/RELEASE.md`
- Modify: `README.md`
- Modify: `/home/simranjit/how-to-when-openclaw-down/agent-integrity/README.md`

- [ ] Document repository/environment/npm configuration and exact status commands.
- [ ] Document forward-only recovery and residual GitHub Free limitations.
- [ ] Run tests, typecheck, build, audit, release scan, package check, diff check, and clean clone smoke.
- [ ] Commit the exact review candidate; do not push, publish, tag, change visibility, or announce.
