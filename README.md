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
