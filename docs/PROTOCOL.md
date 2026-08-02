# Protocol 1-alpha

The canonical interchange format is JSON. Protocol objects contain
`protocolVersion: "1-alpha"`. Complete envelopes bind policy, exact response
content, response sections, source records, decision events, evidence items,
and claims.

Implementations must preserve array order, reject unsupported values, and use
the canonical JSON and SHA-256 rules defined by the conformance tests. A status
is one of `PASS`, `REVIEW`, or `BLOCKED`; blocked findings outrank review
findings. Checker failures must fail closed.

The fixtures under `tests/conformance/fixtures` are language-neutral examples.
They define expected statuses and finding codes. The alpha protocol is not
stable and receipts are not authenticated.
