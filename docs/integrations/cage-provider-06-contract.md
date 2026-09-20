# CAGE Provider 06 and Agent Integrity Sidecar Contract

## Purpose

This document records the proposed boundary between CAGE Provider 06 and the Agent Integrity private verified-release sidecar. It accompanies the full sidecar architecture and implementation plan for cross-project review. It does not claim that the runtime integration is complete or production-ready.

## Ownership boundary

CAGE owns:

- selection of the governed response artifact;
- collection and completeness attestation of approved evidence;
- construction of the canonical Agent Integrity envelope;
- publication of the closed evidence bundle;
- Provider 06 process lifecycle, request authentication, and IPC client behavior;
- routing every outcome through CAGE's `ConsequenceGateway`;
- preservation of signed receipts in CAGE's tamper-evident evidence system;
- dispatch of only the exact response bytes returned by the sidecar.

Agent Integrity owns:

- canonical envelope and receipt semantics;
- strict request and trusted-context validation;
- verification against a private snapshot of the supplied evidence bytes;
- receipt signing and receipt/replay storage;
- result recovery and idempotent redelivery;
- release of exact response bytes only after a valid `PASS` receipt is consumed.

The model or governed payload cannot select trusted policy, trusted roots, decision state, HMAC keys, receipt-signing keys, trust registries, receipt stores, replay stores, clocks, or release behavior.

## CAGE requirements mapping

### 1. Fail-closed boundary and `ConsequenceGateway`

The sidecar returns no releasable bytes for malformed input, authentication failure, replay, timeout, storage failure, unavailable dependencies, `REVIEW`, or `BLOCKED`. Provider 06 must route success, refusal, communication failure, parse failure, and process failure through `ConsequenceGateway`. No alternate dispatch path may bypass that gate.

### 2. Layer 3 vendor isolation

All CAGE-specific sidecar lifecycle, authentication, and HTTP/IPC code remains within `src/integrations/provider_06/`. No Agent Integrity SDK type, process lifecycle, or vendor-specific transport is introduced into the Layer 1 kernel or registered through a domain-plugin entry point.

### 3. Out-of-band trust-anchor resolution

CAGE verifies a receipt signature by resolving its `kid` through a separately provisioned, cached trust manifest. A public key embedded in a receipt is never accepted as its own trust anchor. Key validity windows and revocation state are checked at verification time.

### 4. Refusals as primary evidence

`REVIEW` and `BLOCKED` produce signed receipts but no releasable response bytes. Provider 06 submits those receipts and findings to CAGE's tamper-evident evidence accumulator with the same durability expectations applied to approvals. A refusal is not reduced to an unstructured log message.

### 5. Exact-byte release

For `PASS`, CAGE may dispatch only the response bytes returned by the sidecar after receipt consumption. CAGE must not reconstruct, normalize, translate, append to, or otherwise mutate the response. Any change requires a new verification transaction.

## Initial transport profile

- Same-host deployment.
- HTTP/1.1 over a private Unix domain socket.
- One authenticated CAGE client.
- No public TCP listener.
- Separate Unix identities for CAGE and Agent Integrity.
- HMAC request authentication with durable nonce replay protection.
- Evidence copied from a CAGE-published closed bundle into a sidecar-owned private snapshot before verification.

## Outcome contract

- `PASS`: signed receipt and exact releasable response bytes.
- `REVIEW`: signed receipt, findings, and no releasable response bytes.
- `BLOCKED`: signed receipt, findings, and no releasable response bytes.
- Technical failure: stable service error and no releasable response bytes; no receipt unless a previously completed durable transaction is being returned through an authenticated idempotent retry.

## Explicit non-goals

This proposal does not:

- register Agent Integrity as a CAGE domain plugin;
- change either public Agent Integrity JSON schema;
- claim legal, regulatory, or factual correctness;
- prove CAGE supplied every relevant source;
- authorize arbitrary tool actions;
- define a public or multi-tenant Agent Integrity service;
- claim the runtime integration is complete.

## Review requested from CAGE maintainers

Please review whether the proposed CAGE-side responsibilities match current CAGE architecture, especially:

- mandatory `ConsequenceGateway` routing;
- Provider 06 isolation boundaries;
- trust-manifest ownership and refresh behavior;
- evidence-accumulator durability for `REVIEW` and `BLOCKED`;
- exact-byte downstream dispatch;
- current partner documentation and test locations for the later CAGE PR.

The Agent Integrity implementation remains paused at an internal checkpoint while this contract and the full architecture are reviewed.
