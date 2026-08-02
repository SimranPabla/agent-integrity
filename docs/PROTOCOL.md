# Protocol Reference: `1-alpha`

The Agent Integrity protocol is the language-neutral boundary between agent integrations and the deterministic verifier. The canonical interchange format is JSON.

## Stability

Every protocol object declares `protocolVersion: "1-alpha"`. Alpha objects may change incompatibly before `1.0`. Implementations must reject protocol versions they do not support rather than guessing how to interpret them.

## Complete envelope

A complete response envelope binds all data needed to calculate an outcome:

- a unique run identifier;
- parsed policy and policy digest;
- exact response content;
- response sections with UTF-8 byte ranges, exact-byte SHA-256 digests, and substantive markers;
- approved source records and exact-byte digests;
- decision lifecycle events;
- evidence items;
- claims and their evidence references;
- protocol version and other required metadata.

Verification covers the whole envelope. Protocol `1-alpha` requires ordered sections to partition every UTF-8 response byte exactly once, and every section must have at least one claim.

## Response sections

Sections provide stable identifiers for parts of a human-readable response. Each section contains an inclusive `byteStart`, exclusive `byteEnd`, and `sha256` of those exact UTF-8 bytes. Ranges must be ordered, non-empty, non-overlapping, begin and end on UTF-8 code-point boundaries, start at byte zero, and end at the response byte length. A non-empty response requires at least one section; an empty response has none.

Every section, including one marked non-substantive, must be referenced by at least one claim under the alpha security profile. The `substantive` marker is retained as classification metadata, but cannot weaken claim coverage.

Section identifiers must be unique. Claims referring to missing sections are invalid.

## Claims

Claims represent statements that need integrity treatment. A claim includes:

- a unique identifier;
- one or more response section references;
- a claim type;
- evidence references;
- relevant decision references;
- disclosure metadata when contradictions exist.

Policy determines which claim types require supporting evidence. Missing mandatory evidence is a hard violation. Semantically ambiguous support should produce `REVIEW` through explicit metadata or host policy, not an invented truth score.

## Evidence roles

- `supporting` evidence may satisfy a claim’s evidence requirement.
- `contradictory` evidence conflicts with or weakens a claim and must be disclosed according to policy.
- `contextual` evidence provides background but cannot satisfy a support requirement by itself.

Evidence and claim identifiers must be unique. Dangling references are rejected. Contradictory evidence included in the envelope but undisclosed by the response produces the policy-selected outcome.

## Decision events

Decision state is reconstructed from append-only lifecycle events. Supported states include active, rejected, and superseded. Revisions must be contiguous and non-conflicting. Superseding events must name a valid replacement.

The verifier rejects duplicate events, revision gaps, conflicting state, invalid replacement chains, and claims that rely on a rejected or superseded decision as though it remained active.

## Canonical JSON

Digests are calculated over canonical JSON:

- object keys are sorted deterministically;
- array order is preserved;
- strings are preserved exactly;
- unsupported values are rejected;
- semantically identical object-key ordering produces the same digest;
- number, Unicode, and escaping behavior must match the conformance suite.

Implementations must not hash pretty-printed JSON, source YAML text, or runtime-specific object serialization. Human-authored YAML policy is parsed and normalized before it participates in protocol hashing.

## Hashes

SHA-256 is used for alpha content digests. Source records bind exact bytes. Response binding includes exact response content, so a one-byte mutation changes the envelope digest and invalidates release.

SHA-256 digests provide integrity, not identity. Alpha receipts are unsigned and do not authenticate a producer.

## Outcomes

The status is one of:

- `PASS`: all deterministic rules passed.
- `REVIEW`: no hard violation was found, but configured uncertainty or contradiction requires a human.
- `BLOCKED`: a definite rule violation, malformed bound input, replay, expiry, mutation, or checker failure occurred.

Outcome reduction is deterministic. `BLOCKED` outranks `REVIEW`, and `REVIEW` outranks `PASS`. Integrations must not downgrade a result.

## Findings

Findings are machine-readable records with a stable code, severity/outcome contribution, and safe remediation context. Consumers should use codes for automation and messages for humans. Do not parse prose messages to determine behavior.

New finding codes may be added during alpha. Changing the meaning of an existing code requires protocol compatibility documentation.

## Receipts

An alpha receipt binds:

- protocol and engine version;
- unique run identifier;
- complete envelope digest;
- live bound-content digest;
- outcome;
- creation and expiry timestamps;
- replay/consumption state where applicable;
- receipt self-digest.

Receipts are immutable. Writers must use create-new semantics and refuse overwrite. Recheck must reject changed receipt content, changed envelope content, expiry, duplicate run identifiers, and replay.

Because receipts are unsigned, they are suitable for mutation detection inside one trusted application boundary, not independent provenance verification.

## Strict YAML policy

The policy parser accepts a deliberately restricted subset. It rejects:

- duplicate mapping keys;
- YAML aliases and anchors;
- custom or unsafe tags;
- ambiguous scalar values;
- unknown or malformed required structures.

Policy is normalized into the protocol representation before hashing. Raw YAML formatting is not part of the semantic digest.

## Conformance

Fixtures in `tests/conformance/fixtures` define language-neutral requests, expected outcomes, and finding codes. A compatible implementation should:

1. load every fixture without framework-specific preprocessing;
2. reproduce the expected status;
3. reproduce required finding codes;
4. reproduce canonical digests where the fixture declares them;
5. reject malformed and unsupported protocol versions;
6. pass mutation and replay cases.

Run the TypeScript conformance suite:

```bash
npm test -- tests/conformance
```

Protocol changes must update this document and add fixtures that show both accepted and rejected behavior.
