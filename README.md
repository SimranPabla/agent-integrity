# Agent Integrity

An agent-first, deterministic integrity engine for developers building AI
agents. It checks whether an exact agent response remains consistent with the
approved sources and decisions supplied to it.

> Release-candidate source is currently in private staging. It has no remote
> and is not yet approved for public release.

Agent Integrity is designed for developers building AI agents. The agent
constructs a response envelope automatically; an independent deterministic
engine decides whether the exact response can be released.

## Outcomes

- `PASS`: deterministic integrity checks succeeded.
- `REVIEW`: human judgment is required.
- `BLOCKED`: a definite integrity failure or checker error occurred.

The engine does not prove objective truth, correctness, safety, or judgment.

## Five-minute example

```bash
npm install
npm run build
node examples/basic-agent/index.mjs
```

The example creates a per-run envelope through the TypeScript SDK, verifies it,
and releases the exact response only after `PASS`. Humans maintain one strict
YAML project policy; they do not write a manifest for every response.

## Packages

- `@agent-integrity/protocol`: versioned JSON types.
- `@agent-integrity/core`: deterministic checks, hashing, and receipts.
- `@agent-integrity/sdk`: agent session builder and exact-response release guard.
- `@agent-integrity/cli`: JSON stdin/stdout interoperability.

## What a PASS means

A `PASS` means the exact response is structurally consistent with the approved
sources, decisions, claims, and evidence submitted in its envelope. It does not
mean the sources are true or complete. In particular, the alpha cannot detect
evidence an agent omitted from the envelope. Read `docs/LIMITATIONS.md` and
`docs/THREAT_MODEL.md` before integration.

## Development

Requires Node.js 22 or newer.

```bash
npm install
npm run verify
```

The repository also includes synthetic adversarial examples and
language-neutral conformance fixtures under `tests/conformance/fixtures`.

## CLI

The private alpha CLI reads one JSON object from stdin and writes one JSON
object to stdout. It never echoes response or source content. Available
commands are `validate-policy`, `verify`, `recheck`, and `inspect-receipt`.

```bash
printf '%s' '{"policy":"version: 1\nsources:\n  allowedRoots: [docs/]\ndecisions:\n  path: integrity/decisions.yaml\nrules:\n  requireEvidenceFor: [factual]\n  contradictions: review\n  rejectedDecisions: block\n  responseMutation: block\n  replay: block\n"}' \
  | node packages/cli/dist/cli.js validate-policy
```

Exit codes are stable: `0` for success or `PASS`, `2` for `REVIEW`, `3` for
`BLOCKED`, and `1` for an invalid command, malformed request, or CLI failure.

## Security and licensing

Report vulnerabilities privately as described in `SECURITY.md`. Contributions
are governed by `CONTRIBUTING.md`. The intended public license is Apache-2.0;
final publication remains subject to owner approval.
