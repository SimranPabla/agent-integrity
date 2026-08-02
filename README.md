# Agent Integrity (private staging)

An agent-first, deterministic integrity engine for developers building AI
agents. It checks whether an exact agent response remains consistent with the
approved sources and decisions supplied to it.

This repository is private staging work. It has no remote and is not approved
for public release.

## Outcomes

- `PASS`: deterministic integrity checks succeeded.
- `REVIEW`: human judgment is required.
- `BLOCKED`: a definite integrity failure or checker error occurred.

The engine does not prove objective truth, correctness, safety, or judgment.

## Development

Requires Node.js 22 or newer.

```bash
npm install
npm run verify
```

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
