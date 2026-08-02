# Public Agent Integrity Engine Design

**Status:** Approved for private staging implementation

## Product

This project is a standalone, open-source integrity engine for developers who
build AI agents. An agent prepares an exact response plus structured claims and
evidence. A deterministic engine, separate from the agent, decides whether the
response is safe to release as `PASS`, requires human judgment as `REVIEW`, or
contains a hard integrity failure as `BLOCKED`.

The engine verifies consistency with supplied approved sources and decisions.
It does not prove objective truth, correctness, safety, or good judgment.

## Public/private boundary

This repository is a clean public implementation. It must not contain copied
ARC doctrine, private manifests, verification records, customer data,
credentials, operational controls, or private Git history. ARC's private
validator and the ARC MVP remain separate and unchanged.

## Architecture

- `protocol` defines stable, language-neutral JSON types and schemas.
- `core` canonicalizes inputs, hashes them, rebuilds decision state, validates
  claims/evidence, and calculates deterministic outcomes without calling an LLM.
- `sdk` helps agent developers construct envelopes and release only the exact
  verified response.
- `cli` exposes validation, verification, receipt inspection, and rechecking to
  local workflows and non-TypeScript agents.
- A strict YAML project policy is authored once. Per-run envelopes are generated
  automatically by the SDK as canonical JSON.

## Data flow

1. A developer configures allowed source roots, decision sources, and rules.
2. The agent drafts a response and records its substantive claims.
3. Trusted collectors hash the approved source bytes where possible.
4. The SDK produces a complete response envelope.
5. The core engine validates every deterministic invariant.
6. The engine emits `PASS`, `REVIEW`, or `BLOCKED` and a content-bound receipt.
7. The SDK releases only the exact response bound into that result.

## Outcome policy

- `PASS`: all deterministic checks succeed and no review-only finding remains.
- `REVIEW`: evidence support or contradiction handling requires human judgment.
- `BLOCKED`: definite failure such as mutation, replay, malformed input,
  invalid paths, rejected/superseded decisions, or missing mandatory evidence.
- Internal checker errors fail closed as `BLOCKED` and release nothing.

## V1 scope

- TypeScript SDK and CLI on Node.js 22+
- Stable JSON protocol
- One-time strict YAML policy
- Markdown, text, or structured JSON responses
- Canonical hashing of the complete response context
- Source integrity and approved-root checks
- Decision lifecycle: active, rejected, superseded
- Claim coverage and evidence-role validation
- Contradiction disclosure
- Mutation, expiry, and replay checks
- Machine-readable receipts and local-first operation
- Synthetic examples, conformance tests, and adversarial tests

Signing and key rotation are protocol requirements, but implementation may land
after unsigned local receipts if the receipt format is explicitly marked alpha.

## Deferred

Hosted service, dashboards, multi-tenancy, action control, coding-runtime
interception, merge gating, MCP integration, Trust Briefs, Python SDK, and
automated semantic truth evaluation are not part of V1.

## Security boundaries

The agent may propose claims and evidence mappings but cannot declare a pass.
The verifier is deterministic and has no LLM dependency. Source paths must stay
inside configured roots. YAML duplicate keys, aliases, custom tags, and
ambiguous scalar coercions are rejected. Receipts bind the exact response,
policy, source state, decisions, claims, engine version, run identifier, and
expiry. Rechecking rereads all bound subjects.

## Testing

Every behavior is developed test-first. Conformance tests cover canonical JSON,
hash stability, protocol validation, decision reduction, claim coverage, and
status calculation. Adversarial tests cover path traversal, symlinks, malformed
YAML, duplicate keys, response/source mutation, replay, expired receipts,
decision revival, contradiction hiding, and checker failure.

## V1 success

A developer can add the SDK to a basic TypeScript agent in under 30 minutes,
without hand-writing per-run manifests. One changed response or source byte
invalidates verification. Definite integrity failures block, uncertainty routes
to review, and all examples run without ARC infrastructure.
