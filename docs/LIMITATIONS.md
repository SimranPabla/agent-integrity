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

## Alpha receipts are unsigned

Version `1-alpha` receipts are immutable local records with content digests,
expiry checks, duplicate-run protection, and live-envelope rechecking. They can
detect changed receipt content or changed bound inputs, but they do not prove
who created the receipt. Do not treat an alpha receipt as third-party
attestation or identity proof. Cryptographic signing, key rotation, and
revocation are required before making that claim.
