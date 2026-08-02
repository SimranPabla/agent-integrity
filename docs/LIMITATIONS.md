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

## Filesystem races and platform limits

Trusted verification recollects local source files and compares normalized path, byte size, and SHA-256. The collector opens the resolved final path with `O_NOFOLLOW` where available and checks file identity and timestamps before and after the read.

Portable Node.js APIs do not provide descriptor-relative traversal for every parent directory. A local attacker who can rewrite source-tree directories during collection may still race path resolution and opening. Keep approved source trees non-writable by untrusted users and processes during verification. Platforms that do not expose `O_NOFOLLOW` have weaker final-component symlink-race protection. Agent Integrity does not defend against a malicious kernel, compromised filesystem, or attacker with equivalent access to the verifier process.

## Semantic ambiguity

The deterministic engine validates structure, lifecycle state, declared roles, and digests. It does not use an LLM to decide whether a passage genuinely supports a claim. Agent-generated mappings can be semantically weak even when structurally valid.

## Decision dependencies and history

Trusted verification validates the `decisionIds` declared on each claim against the current configured YAML registry snapshot. It cannot determine that a claim semantically relies on another decision omitted by the agent or host. An empty list means only that no dependency was declared, not that no dependency exists.

Within the current snapshot, the parser enforces encountered event order, contiguous revisions, and valid lifecycle transitions. It does not consult a digest or checkpoint from an earlier run. If an actor trusted to manage the registry truncates or rewrites that file and then constructs a matching envelope and digest, the verifier cannot recover the previous history or detect the rewrite. Cross-run append-only preservation requires trusted host/storage controls, backups, or a future authenticated checkpoint mechanism.

Mitigation:

- define evidence requirements by claim type;
- route ambiguous support to `REVIEW`;
- expose evidence excerpts to human reviewers;
- add domain-specific deterministic checks outside the core;
- never label a model-based relevance score as deterministic proof.

## Signed receipts are not yet single-use

Receipt `2-alpha` uses Ed25519 to authenticate a producer and binds issuer, audience, purpose, nonce, engine version, policy, envelope, outcome, and timestamps. Trusted creation and recheck recollect declared source bytes.

Receipts do not yet have atomic consumption state. Recheck does not consume a receipt or prevent repeated use of the same valid receipt. An actor who steals a signing key can forge its producer identity; an actor who changes the trusted-key configuration can alter the trust boundary.

Do not treat a signature as proof that response claims are true. Production use still requires protected key custody, rotation, revocation distribution, and a documented trust-root ceremony.

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

`1-alpha` is not stable. Fields, finding codes, receipt behavior, and package APIs may change before `1.0`. Pin exact versions, store the engine version alongside receipts in host metadata, and test upgrades against conformance fixtures. The alpha receipt itself does not contain an engine-version field.

## Availability and resource exhaustion

The verifier is not designed as a hostile multi-tenant network service. Trusted source collection defaults to 16 MiB per source and 64 MiB total, checks the file size before reading, and retains bounded source buffers while validating evidence anchors. Applications should lower these limits where practical and must still enforce request-size, record-count, and execution-time limits before exposing verification over a network.

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
