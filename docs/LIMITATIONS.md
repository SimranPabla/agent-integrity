# Limitations

This engine verifies deterministic consistency with the approved material
submitted in a complete response envelope. It does not prove truth, sound
reasoning, safety, code correctness, or that the underlying decisions are wise.

## Omitted evidence

The engine detects a contradiction only when the contradictory evidence is
present in the envelope. An agent can currently omit a known source or omit a
contradictory item before verification. A `PASS` therefore means the response
is consistent with the submitted evidence; it does not mean the evidence set
is complete.

Trusted evidence collection is planned to reduce this risk. Integrators should
independently capture source access and compare the collected set with the
agent-generated envelope when the use case requires stronger assurance.
