# Threat Model

## Protected subject

The exact agent response and its relationship to explicitly approved sources,
decisions, policy, claims, and evidence mappings.

## Initial adversaries

- An agent omits a substantive claim from verification.
- An agent cites contextual or contradictory material as support.
- A rejected or superseded decision is revived.
- Approved sources or the response change after verification.
- A stale receipt is replayed against a new response or context.
- A malformed input or checker error is mistaken for a pass.

## Trust boundary

The agent may construct an envelope, but only the independent deterministic
engine calculates the outcome. Engine errors fail closed.

## Non-goals

The engine does not establish that sources are true, decisions are wise, prose
is logically sound, code is correct, or an agent action is safe.

## Known evidence-completeness limit

The engine can detect contradictory evidence that is included in the envelope
but not disclosed in the response. It cannot, by itself, detect evidence an
agent discovered and then omitted from the envelope entirely. The envelope is
therefore not proof that the agent supplied every relevant source.

Agent integrations should use trusted evidence collectors or independently
record source access where possible. Until that collection layer exists, users
must treat a `PASS` as consistency with the submitted evidence, not proof that
the evidence set is complete.
