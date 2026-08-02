# Contributing

The project welcomes focused changes that strengthen deterministic response
integrity for agent developers.

1. Open an issue describing the failure mode or protocol change.
2. Add a failing test or language-neutral conformance fixture.
3. Implement the smallest compatible change.
4. Run `npm run verify` and `npm audit --audit-level=high`.
5. Update the threat model or limitations when guarantees change.

Never submit real customer data, private policies, credentials, internal ARC
artifacts, or generated verification records containing sensitive metadata.
Protocol changes require compatibility notes and must not silently reinterpret
an existing protocol version.

By contributing, you agree that your contribution is licensed under the
Apache License 2.0.
