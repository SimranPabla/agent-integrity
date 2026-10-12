# Protocol Reference: `1-alpha`

The Agent Integrity protocol is the JSON interchange boundary between agent integrations and the deterministic verifier. TypeScript is the reference implementation; other languages can implement the schemas and conformance fixtures experimentally.

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

Each evidence item may carry an exact source byte anchor with inclusive `byteStart`, exclusive `byteEnd`, and SHA-256. Trusted verification requires the anchor, recollects the referenced source, checks the range, and hashes those actual bytes. The pure `verifyEnvelope` function remains a structural verifier and does not claim live filesystem verification; release and CLI verification use the trusted asynchronous path.

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

Decision state is reconstructed from lifecycle events in the current trusted YAML snapshot. Supported states include active, rejected, and superseded. Revisions for each decision must appear in append order, remain contiguous and non-conflicting, and may interleave with events for other decisions. Superseding events must name a valid replacement.

Each claim carries a `decisionIds` list. The list may be empty when the envelope declares no durable-decision dependency. Trusted verification loads the YAML file configured by `policy.decisions.path`, hashes its exact bytes, and requires both `decisionRegistryDigest` and the envelope's complete `decisions` snapshot to match that registry. It rejects duplicate events, revision gaps, out-of-order revisions, conflicting state, invalid replacement chains, and declared references to unknown, rejected, or superseded decisions. Rejected or superseded decisions that no claim references remain valid registry history and do not block an unrelated response.

These checks do not discover semantic dependencies missing from `decisionIds`. They prove append order and lifecycle only inside the current snapshot: no prior registry digest or checkpoint is consulted. Preserving history against cross-run truncation or rewriting is a trusted host/storage responsibility.

The registry YAML has exactly two root fields:

```yaml
version: 1
events:
  - eventId: approve-window-1
    decisionId: maintenance-window
    revision: 1
    action: activate
```

Aliases, custom tags, duplicate keys, unknown fields, invalid event shapes, and invalid lifecycle sequences are rejected. The configured path must be relative and resolve inside the trusted project root.

## Canonical JSON

Digests are calculated over canonical JSON:

- object keys are sorted deterministically;
- array order is preserved;
- strings are preserved exactly;
- unsupported values are rejected;
- semantically identical object-key ordering produces the same digest;
- number, Unicode, and escaping behavior must match the conformance suite.

The exported `canonicalJson` and `sha256Canonical` helpers traverse arrays using one captured own length data descriptor (integer uint32, non-enumerable, non-configurable; either writable flag), then each required own data-index descriptor. Holes, inherited required indices and own index accessors now throw TypeError at the indexed path without invoking index accessors. Caller map output is no longer honored; map, join, constructor/species, toJSON and iterator hooks are not accessed. Caller inputs are not cloned, frozen or mutated.

Dense subclasses and custom-prototype arrays, frozen arrays and non-enumerable/non-writable data indices remain supported. Dense null-prototype arrays are accepted additively. Unrelated string/symbol array properties are ignored without reading their values, including accessor extras. This intentionally lossy projection is not closed JavaScript admission or a new collision-resistance guarantee; previously accepted non-JSON projections may change or reject. Supported dense JSON canonical bytes/digests remain unchanged. The record domain remains plain/null-prototype records with sorted enumerable own string keys: dangerous keys, accessors and undefined values reject; hidden and symbol properties remain ignored. Unsupported values, nonfinite numbers and cycles still reject; shared noncyclic containers are counted separately per occurrence.

Limits remain container depth 64 (root zero), 100,000 container occurrences and 16 MiB UTF-8 per string. Primitives do not consume the container count or container-depth checks. There is no per-array, primitive-node, key-byte or aggregate transport budget; very large dense arrays can still consume substantial time/memory. Internal push/join use trusted host intrinsics. Hostile Proxy traps, globally modified intrinsics/prototypes and concurrent hostile mutation are outside side-effect-free guarantees; no Proxy detection or hardened-realm claim is made.

This helper repair does not loosen the stricter capture admission or fix signed outer-transaction ownership. No schema, hash algorithm/version or receipt migration is introduced, nor is valid-envelope/signature forgery established. Reverting restores known unsafe sparse/hook behavior, not a security recovery; halt dependent untrusted use rather than treating revert as recovery. Rejected/non-JSON inputs are not automatically migrated or reissued.

Implementations must not hash pretty-printed JSON, source YAML text, or runtime-specific object serialization. Human-authored YAML policy is parsed and normalized before it participates in protocol hashing.

## Hashes

SHA-256 is used for alpha content digests. Source records bind exact bytes. Response binding includes exact response content, so a one-byte mutation changes the envelope digest and invalidates release.

SHA-256 digests alone provide integrity, not identity. Receipt `2-alpha` adds Ed25519 producer authentication; its assurance depends on trusted-key configuration and private-key custody.

## Outcomes

The status is one of:

- `PASS`: all deterministic rules passed.
- `REVIEW`: no hard violation was found, but configured uncertainty or contradiction requires a human.
- `BLOCKED`: a definite rule violation, malformed bound input, changed-envelope receipt use, expiry, mutation, or checker failure occurred.

Outcome reduction is deterministic. `BLOCKED` outranks `REVIEW`, and `REVIEW` outranks `PASS`. Integrations must not downgrade a result.

## Findings

Findings are machine-readable records with a stable code, severity/outcome contribution, and safe remediation context. Consumers should use codes for automation and messages for humans. Do not parse prose messages to determine behavior.

New finding codes may be added during alpha. Changing the meaning of an existing code requires protocol compatibility documentation.

## Receipts

A `2-alpha` receipt binds:

- protocol and receipt version;
- unique run identifier;
- complete envelope digest;
- outcome;
- creation and expiry timestamps;
- engine version, issuer, audience, purpose, nonce, and policy digest;
- Ed25519 signing key ID and signature;
- receipt self-digest.

Receipt creation requires trusted verification and recollects every declared source before signing and writing. Recheck verifies the Ed25519 signature against an explicit trusted-key set, rejects revoked/unknown keys, checks issuer/audience/purpose/engine/policy/time bindings, and recollects source bytes.

Receipt `2-alpha` authenticates its configured producer and can be consumed exactly once through `FileReceiptStore`. Every store operation acquires the same create-once owner-token lock; locks are never removed based on age. A crash may leave the store locked until an offline operator supplies the exact recorded owner token. Authoritative records are written to private staging files, fsynced, published without replacement by hard link, and followed by directory fsync where supported. Transaction intent is committed before quota. Consumption publishes one digest-specific record, so exactly one consumer succeeds while all participants use this store.

The issued record stores the complete receipt as the authoritative recovery copy. Output failure retains committed issuance; `completeReceiptFile` finishes it later. Interrupted destructive cleanup is represented by a durable journal and resumed with `reconcileCleanup`. Pre-commit recovery must acquire the same store lock, requires the exact transaction ID, and cannot race a live issuer. These are local-filesystem controls, not distributed transactions; power-loss guarantees remain platform-dependent. Consumed tombstones continue counting toward quota because deletion would weaken replay protection.

## Strict YAML policy

The policy parser accepts a deliberately restricted subset. It rejects:

- duplicate mapping keys;
- YAML aliases and anchors;
- custom or unsafe tags;
- ambiguous scalar values;
- unknown or malformed required structures.

Policy is normalized into the protocol representation before hashing. Raw YAML formatting is not part of the semantic digest.

## Conformance

Fixtures in `tests/conformance/fixtures` define JSON requests, expected outcomes, and finding codes. Another implementation should:

1. load every fixture without framework-specific preprocessing;
2. reproduce the expected status;
3. reproduce required finding codes;
4. reproduce canonical digests where the fixture declares them;
5. reject malformed and unsupported protocol versions;
6. pass mutation, expiry, and changed-envelope receipt cases.

Run the TypeScript conformance suite:

```bash
npm test -- tests/conformance
```

Protocol changes must update this document and add fixtures that show both accepted and rejected behavior.
