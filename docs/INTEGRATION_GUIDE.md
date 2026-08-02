# TypeScript Integration

Create one project policy, then create an `AgentIntegritySession` for each
response. Add the sources, decision events, evidence items, claims, response
sections, and exact response bytes observed during that run. Call
`verifyEnvelope`, then pass the unchanged envelope and result to
`releaseVerifiedResponse`.

Only a `PASS` result contains `response`. `REVIEW`, `BLOCKED`, malformed input,
and post-verification mutation return no response.

See `examples/basic-agent/index.mjs` for a complete runnable example. A real
integration should collect source reads independently when possible; relying
only on agent-declared evidence cannot detect omitted sources.
