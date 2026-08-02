# Limitations

Agent Integrity verifies deterministic consistency with the approved material submitted in a complete response envelope. Understanding these limits is part of using the tool correctly.

## `PASS` is not truth

A `PASS` means the supplied envelope met the configured deterministic rules and the released response bytes match the checked response. It does not mean:

- the source documents are factually correct;
- the evidence set is complete;
- the claim logically follows from the evidence;
- a recommendation is wise;
- the response is safe, unbiased, or legally compliant;
- generated code works;
- an agent was authorized to perform an action.

Use ordinary domain review, testing, and safety controls alongside Agent Integrity.

## Omitted evidence

The engine detects contradictory evidence only when that evidence is present in the envelope. An agent can omit a known source or contradictory item before verification. A `PASS` therefore means consistency with the submitted evidence, not proof that the evidence set is complete.

Mitigation:

- record retrieval and file-read events in the application host;
- compare host-observed sources with the envelope;
- keep source roots narrow and reviewed;
- use human review for high-impact answers;
- treat unexplained missing collector records as `REVIEW` or `BLOCKED` in the host.

There is no universal trusted collector in the alpha release.

## Semantic ambiguity

The deterministic engine validates structure, lifecycle state, declared roles, and digests. It does not use an LLM to decide whether a passage genuinely supports a claim. Agent-generated mappings can be semantically weak even when structurally valid.

Mitigation:

- define evidence requirements by claim type;
- route ambiguous support to `REVIEW`;
- expose evidence excerpts to human reviewers;
- add domain-specific deterministic checks outside the core;
- never label a model-based relevance score as deterministic proof.

## Unsigned alpha receipts

Protocol `1-alpha` receipts detect mutation through content digests, expiry checks, duplicate-run protection, and live-envelope rechecking. They do not authenticate who created the receipt.

Do not use them as third-party attestations, signed provenance, or identity proof. Cryptographic signing, key rotation, revocation, and a documented trust-root ceremony are required before making those claims.

## Host bypass

The SDK cannot stop a malicious or incorrectly wired host from sending the raw model draft through another code path. It also cannot retract tokens already streamed to a user.

Mitigation:

- centralize response release;
- return user-visible bytes only from the release guard;
- buffer drafts rather than streaming;
- test alternate routes and exception paths;
- isolate the verifier process when the risk justifies it.

## Local storage and confidentiality

The project is local-first, but local does not automatically mean confidential. Envelopes can contain complete responses, source metadata, paths, and evidence. Receipts can reveal timing and decision identifiers.

The alpha release does not encrypt files, redact arbitrary application logs, manage retention, or secure backups. The host owns filesystem permissions, encryption, access control, and deletion policy.

## Runtime support

The supported runtime is Node.js 22+. Browsers, edge runtimes, Deno, Bun, and older Node.js releases are not tested. The CLI can be called from any language able to start a process and exchange JSON, but that language is responsible for subprocess lifecycle and safe output handling.

## Protocol stability

`1-alpha` is not stable. Fields, finding codes, receipt behavior, and package APIs may change before `1.0`. Pin exact versions, store the engine version with receipts, and test upgrades against conformance fixtures.

## Availability and resource exhaustion

The verifier is not designed as a hostile multi-tenant network service. Very large envelopes, deeply nested structures, or excessive numbers of records can consume memory and CPU. Applications should enforce request-size and execution-time limits before exposing verification over a network.

## No automatic policy quality review

The engine enforces the policy it receives. A permissive policy can produce weak passes; a strict policy can create excessive reviews or blocks. Start with deterministic hard failures and route uncertainty to `REVIEW`. Measure outcomes before tightening policy.

## Alpha deployment recommendation

Use Agent Integrity first in development, evaluation, and low-risk internal workflows. Measure:

- pass, review, and block rates;
- common finding codes;
- false-review and false-block reports;
- omitted-source incidents;
- integration bypass attempts;
- time required for human review.

Do not make it the sole control for safety-critical, medical, legal, financial, or other high-impact decisions.
