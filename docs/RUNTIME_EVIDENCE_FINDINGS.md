# Runtime Evidence Findings and Hardening Requirements

## Outcome

Agent Integrity has demonstrated useful fail-closed behavior in a bounded
internal pilot, but the audit also found integration gaps that can make a
technically valid verdict weaker than users assume. This document records the
sanitized evidence, limits the claim that can be made from it, and defines the
requirements for a stronger runtime integration.

This is a findings and planning document. It does not change the protocol,
runtime, schemas, or current guarantees.

## Audit scope

The audit examined two internal integration patterns:

1. a content-release workflow using the public Agent Integrity packages; and
2. a separate artifact-generation workflow using a private deterministic
   validator with similar response-and-evidence concepts.

Only aggregate, non-identifying observations are included here. The audit did
not copy customer data, private source content, credentials, repository names,
local paths, account identifiers, or approval messages into this repository.

### Evidence examined

- repository history and integration code;
- current automated tests;
- stored response envelopes, verification records, and release files;
- historical commits needed to replay retained runs;
- approval and invalidation state transitions;
- current manifests and source references;
- a generated artifact compared with its approved source material.

### Evidence strength

- **Directly reproduced:** current tests, retained-record replay, manifest
  failures, and exact-byte comparisons.
- **Corroborated from retained local evidence:** approval state transitions and
  historical release decisions.
- **Not independently recoverable:** one early run whose exact supporting
  source bytes were never retained.

## What worked

### The completion gate changed behavior

In the public-package pilot, the gate did more than produce a report. A real
change moved through these states:

1. `BLOCKED` because required evidence was absent;
2. `REVIEW` after evidence existed but approval was missing;
3. human rejection;
4. invalidation of an earlier approval after protected bytes changed;
5. fresh approval for the changed bytes; and
6. `PASS` followed by release of the exact verified response.

This is useful evidence that a completion gate can prevent a premature
completion claim and can force evidence and approval to catch up with the
actual protected subject.

### Current integration tests pass

All 18 current integrity-focused tests in the audited public-package
integration passed. They exercise exact response binding, status handling,
approval freshness, and release behavior.

### Retained releases usually replay

Nine stored release files were inspected: eight historical pilot releases and
one synthetic test fixture. Every release matched its recorded envelope
response byte-for-byte. Eight of the nine historical envelopes reproduced a
`PASS` when checked with the historical application and verifier revisions.

The remaining historical run did not reproduce because its exact supporting
source bytes were not committed or otherwise retained. This is an evidence
retention failure, not evidence that the original verdict was wrong.

### Fail-closed states were respected

One audited workflow remained in `REVIEW` and had no release file. The audit
found no evidence that a `REVIEW`, `BLOCKED`, malformed, or error result was
released through the inspected integration path.

## What did not work well enough

### 1. Durable evidence was optional in practice

Some run and evidence directories were ignored or treated as disposable local
state. A verifier can bind exact bytes at check time, but later auditability is
lost when those bytes, the envelope, the policy, or the approval evidence are
not retained together.

**Risk:** a valid historical result becomes non-reproducible, and reviewers can
no longer distinguish a correct old verdict from missing evidence.

### 2. Verifier identity was not fully bound

Historical replay required manually checking out an older verifier revision.
The release evidence did not independently identify the verifier repository,
commit, build digest, or package digest that produced the verdict.

**Risk:** a record may bind the response and sources while leaving ambiguity
about which verifier implementation interpreted them.

### 3. Approval evidence relied on local unsigned state

The pilot correctly invalidated stale approval when protected bytes changed,
but approval receipts were local JSON records without a producer signature or
another authenticated authority proof.

**Risk:** the integrity mechanism can prove internal consistency without
proving who authorized the approval record.

### 4. Request verification and use were separate operations

The inspected integration verified a request and then reopened it for use.
The same pattern can occur when an application verifies an artifact path and
later reads that path again.

**Risk:** protected bytes can change between check and use. Path or digest
agreement at verification time does not prevent a later read from observing
different bytes.

### 5. Artifact evidence was not always the protected subject

In the second workflow, the gate verified a short descriptive response about a
generated artifact rather than the artifact bytes themselves. The generated
artifact contained a material contradiction with an approved source, yet the
verdict passed because that claim was outside the checked response.

**Risk:** a correct verdict can be attached to the wrong subject. The verifier
did what it was asked to do, but the integration created misleading assurance.

### 6. Artifact hashes were not always recollected at release

One integration stored an artifact hash in a manifest but did not make the
final verifier reopen the artifact and recompute the digest immediately before
release.

**Risk:** a manifest can remain internally consistent while the released file
has changed.

### 7. Records were durable only as local files

Stored records did not consistently package the exact response, source
snapshots or immutable source references, active policy, decision state,
approval proof, verifier identity, and released artifact in one durable unit.

**Risk:** individual files survive while their relationships and provenance do
not.

### 8. Usage could not be measured reliably

The repositories had no privacy-preserving usage telemetry or canonical local
run index. Record counts overstated independent use in one workflow because
seven record files represented only three unique response digests.

**Risk:** file counts can be mistaken for adoption, distinct checks, or
business value.

## Correct interpretation

The evidence supports this narrow claim:

> Agent Integrity can enforce exact-byte, fail-closed completion gating in a
> bounded local integration when the host routes every release through the
> guard and retains the required inputs.

The evidence does **not** establish:

- production-scale adoption;
- objective truth or semantic correctness;
- complete evidence retrieval;
- authenticated human identity;
- protection from a malicious host or same-user process;
- distributed replay protection;
- durable historical reproducibility without an evidence-retention policy; or
- integrity of an artifact that was not itself bound and recollected.

## Hardening contract

The following requirements should be satisfied before describing an
integration as a durable runtime evidence gate.

### H1. Name the protected subject

Every integration must declare one or more protected subjects by media type,
logical role, byte length, and SHA-256 digest. A description of an artifact is
not a substitute for the artifact itself.

**Acceptance evidence:** changing one byte of any protected subject invalidates
the result and prevents release.

### H2. Capture once, verify once, release the captured bytes

The host must capture request, response, and artifact bytes into immutable
objects or open file descriptors. Verification and release must use those same
captured bytes. The integration must not verify a path and later reopen it for
release.

**Acceptance evidence:** an adversarial test swaps the path target after
verification and confirms that only the captured bytes can be released.

### H3. Recollect declared external sources into stable byte objects

The final verifier must recollect every path-based source into a stable byte
object, compare file identity around the read, and verify size and digest. An
artifact intended for release must always be captured; an integration that
cannot release the captured artifact bytes must fail closed rather than reopen
the path after verification.

**Acceptance evidence:** source and artifact mutations between draft creation
and release fail closed, and the release API has no path-based fallback.

### H4. Bind verifier identity

Every durable record must include a closed verifier identity containing the
protocol version plus an immutable implementation identifier such as a Git
commit and build or package digest.

**Acceptance evidence:** replay refuses an unrecognized or mismatched verifier
identity.

### H5. Authenticate approval authority

Where a verdict depends on human approval, the approval must bind the protected
subject digest, decision, scope, issuer, issue time, expiry, and nonce. The
integration must verify an authenticated signature or an equivalent trusted
authority receipt.

**Acceptance evidence:** changed subjects, expired approvals, unknown issuers,
and altered approval fields fail closed.

### H6. Persist an atomic evidence bundle

A successful release must create one content-addressed bundle containing or
immutably referencing:

- protected subject bytes and digests;
- response envelope and normalized response bytes;
- source snapshots or immutable source references;
- effective policy and decision snapshot;
- approval receipts;
- verifier identity;
- verdict and findings;
- release event, destination class, and exact released-byte digest.

Bundle publication must be atomic and refuse overwrite.

**Acceptance evidence:** a clean checkout can reproduce the verdict using only
the bundle and explicitly documented trust anchors.

### H7. Sign durable receipts where the threat model requires it

Local self-digests detect accidental mutation but do not authenticate a
producer. Cross-process, cross-host, or third-party reliance requires a signed
receipt with key identity, validity, revocation, and rotation rules.

**Acceptance evidence:** altered receipts, unknown keys, revoked keys, and
out-of-window signatures fail closed.

### H8. Count unique checks, not files

Privacy-preserving metrics must distinguish attempts, unique protected-subject
digests, verdicts, releases, rechecks, failures, and reproducible historical
runs. Metrics must not contain response text, source content, local paths, or
personal identifiers.

**Acceptance evidence:** duplicate records for one subject do not inflate the
unique-subject count.

## Implementation sequence

1. Define the protected-subject and verifier-identity schemas.
2. Add immutable byte capture and release APIs.
3. Add direct artifact recollection for path-based integrations.
4. Define authenticated approval receipts and trust-anchor handling.
5. Define the atomic evidence-bundle layout and retention policy.
6. Add language-neutral fixtures for byte swaps, stale approvals, verifier
   mismatch, incomplete bundles, and replay.
7. Add privacy-preserving local metrics derived from canonical run IDs and
   subject digests.
8. Update the threat model, protocol, integration guide, limitations, and
   compatibility guidance before changing public behavior.

Protocol-visible changes require a separate design review, versioning decision,
schemas, conformance fixtures, and migration guidance. This document does not
authorize silently changing the current alpha protocol.

## Completion gate for this hardening work

The work is complete only when all of the following are demonstrated at one
exact repository revision:

- every requirement H1-H8 has an automated adversarial test;
- a synthetic end-to-end integration releases only captured verified bytes;
- a clean environment reproduces a retained historical bundle;
- no `REVIEW`, `BLOCKED`, malformed, expired, or internal-error path releases;
- the public documentation states the remaining limits without widening the
  meaning of `PASS`; and
- the final review records the exact commit and test commands used.
