# CAGE Provider 06 and Agent Integrity Sidecar Contract

## Purpose

This document records the proposed boundary between CAGE Provider 06 and the Agent Integrity private verified-release sidecar. It accompanies the full sidecar architecture and implementation plan for cross-project review. It does not claim that the runtime integration is complete or production-ready.

## Ownership boundary

CAGE owns:

- selection of the governed response artifact;
- collection and completeness attestation of approved evidence;
- construction of the canonical Agent Integrity envelope;
- publication of the closed evidence bundle;
- Provider 06 process lifecycle, possession of the CAGE-side HMAC secret copy, construction of the required authentication headers, and IPC client behavior;
- routing every outcome through CAGE's `ConsequenceGateway`;
- preservation of signed receipts in CAGE's tamper-evident evidence system;
- dispatch of only the exact response bytes returned by the sidecar.

Agent Integrity owns:

- canonical envelope and receipt semantics;
- strict request and trusted-context validation;
- server-side HMAC verification and durable cross-key nonce replay enforcement;
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

CAGE treats `receipt.signature.keyId` as the receipt `kid` and resolves it only through a separately provisioned, authenticated trust manifest. A public key embedded in a receipt or sidecar response is never accepted as its own trust anchor.

The trust manifest is one RFC 8785 canonical JSON object with this exact closed schema and no unknown or optional fields:

```ts
type CageReceiptTrustManifestV1 = Readonly<{
  version: "1";
  generation: number;
  issuedAt: CanonicalUtcTimestamp;
  validUntil: CanonicalUtcTimestamp;
  receiptProfile: Readonly<{
    issuer: BoundedString;
    audience: BoundedString;
    purpose: BoundedString;
    engineVersion: BoundedString;
    maximumReceiptLifetimeSeconds: number;
    maximumFutureSkewSeconds: number;
  }>;
  keys: readonly Readonly<{
    keyId: SafeId;
    algorithm: "Ed25519";
    publicKey: CanonicalBase64Url32;
    notBefore: CanonicalUtcTimestamp;
    notAfter: CanonicalUtcTimestamp;
    revokedAt: CanonicalUtcTimestamp | null;
  }>[];
  signatureAlgorithm: "Ed25519";
  authorityKeyId: SafeId;
  manifestDigest: LowercaseSha256;
  signature: CanonicalBase64Url64;
}>;
```

The raw canonical manifest is at most 256 KiB. `generation`, `maximumReceiptLifetimeSeconds`, and `maximumFutureSkewSeconds` are positive safe integers; the two duration fields may not exceed CAGE's independently configured ceilings. `BoundedString` is non-empty UTF-8 of at most 256 bytes. `SafeId` uses `[A-Za-z0-9][A-Za-z0-9._-]{0,127}`. Timestamps use RFC 3339 UTC with exactly three fractional-second digits and terminal `Z`. `keys` contains 1 through 128 entries sorted bytewise by unique `keyId`. Each key requires `notBefore < notAfter`; `revokedAt` is null or falls inside that interval. CAGE treats a non-null `revokedAt` as revoked, and otherwise accepts the key only while `notBefore <= now < notAfter`. Future revocation scheduling is not part of this profile. Every key algorithm is exactly `Ed25519`, and every `publicKey` is unpadded canonical base64url encoding of exactly 32 raw Ed25519 public-key bytes. `issuedAt < validUntil`; a manifest is usable only while `issuedAt <= now + maximumFutureSkewSeconds` and `now < validUntil` at a fresh CAGE host time.

`authorityKeyId` resolves only through CAGE's pinned manifest-authority configuration, provisioned through CAGE's deployment/configuration channel rather than by the sidecar response. That configuration stores the authority public key in the same 32-byte raw, unpadded canonical base64url format.

`manifestDigest` is the lowercase hexadecimal SHA-256 of RFC 8785 canonical manifest bytes with only `manifestDigest` and `signature` omitted; `signatureAlgorithm` and `authorityKeyId` remain in the digest input. The signature preimage is the exact UTF-8 bytes of `cage-agent-integrity-trust-manifest-v1`, followed by one `0x00` byte, followed by the 32 raw bytes decoded from `manifestDigest`. `signature` is the unpadded canonical base64url encoding of the resulting 64-byte Ed25519 signature (86 characters). CAGE rejects padding, non-canonical encodings, wrong decoded lengths, any other algorithm, or an unknown authority key ID before using a receipt key from the manifest.

CAGE persists the highest accepted `(generation, manifestDigest)` pair. A lower generation is rollback and is rejected even when signed. An equal generation is accepted only when its digest exactly matches the persisted digest; an equal-generation digest conflict is rejected and cannot replace the cache. Only a strictly greater valid generation may atomically replace the pair and cached manifest. Refresh may replace the cache only after the complete new manifest, authority signature, generation, digest, validity interval, and revocation data validate. If refresh fails, CAGE may use the current cached manifest only until `validUntil`; a missing, expired, rolled-back, conflicting, malformed, or unauthenticated manifest, an unknown receipt `kid`, or a key that is revoked or outside its validity window is a fail-closed non-admitting result with no downstream bytes. This bounds how long cached revocation state may be used and makes refresh failure behavior deterministic.

### 4. Refusals as primary evidence

`REVIEW` and `BLOCKED` produce signed receipts but no releasable response bytes. Provider 06 submits those receipts and findings to CAGE's tamper-evident evidence accumulator with the same durability expectations applied to approvals. A refusal is not reduced to an unstructured log message.

### 5. Exact-byte release

For `PASS`, CAGE first validates the closed service response and requires `response.requestId` to equal the original request ID. It resolves the receipt key from the accepted trust manifest and verifies the Ed25519 signature. It then requires the receipt issuer, audience, purpose, engine version, and key ID to equal Provider 06's independently configured expected values; requires the receipt key to be currently valid and not revoked; parses `createdAt` and `expiresAt`; rejects invalid ordering, excessive configured lifetime, future issuance beyond configured skew, or expiry at a fresh CAGE host time; recomputes the trusted policy digest; and enforces the same receipt metadata and policy bindings as Agent Integrity's core recheck. CAGE never accepts these expected values from the receipt or sidecar response itself.

CAGE recomputes the canonical request envelope digest and requires it to equal `receipt.envelopeDigest`, requires the wrapper, verification, and receipt statuses all to be `PASS`, and requires RFC 8785 canonical bytes of the wrapper `verification` to equal RFC 8785 canonical bytes of `receipt.verification`. It applies the same canonical-equality rule to receipt-bearing `REVIEW`, `BLOCKED`, and `RELEASE_REFUSED` responses; wrapper findings are never independent evidence.

CAGE then canonically base64-decodes `releasedResponse.bytes`, requires those decoded bytes to equal the exact UTF-8 bytes of the original request envelope's `response.content`, computes SHA-256 over the decoded bytes, and requires that digest to equal `releasedResponse.sha256`. CAGE dispatches that decoded sidecar-returned byte buffer itself. It must not dispatch reconstructed request bytes or normalize, translate, append to, truncate, or otherwise mutate the returned buffer. Any mismatch fails closed, and any intended change requires a new verification transaction.

For `RELEASE_REFUSED`, CAGE requires the exact closed sidecar shape, `verification.status === receipt.verification.status === "PASS"`, `release.status` of `REVIEW` or `BLOCKED`, code `RECEIPT_RECHECK_REFUSED`, `retryable: false`, and no `releasedResponse`. It validates and preserves the signed receipt, preserves the terminal release-refusal response as associated evidence, routes the outcome through `ConsequenceGateway` as non-admitting, and never treats the prospective PASS receipt alone as release authority. Authenticated retries must return byte-identical canonical response bytes for the persisted completed transaction.

## Initial transport profile

- Same-host deployment.
- HTTP/1.1 over a private Unix domain socket.
- One authenticated CAGE client.
- No public TCP listener.
- Separate Unix identities for CAGE and Agent Integrity.
- CAGE constructs HMAC request headers from its protected client-side key copy; the sidecar verifies the MAC and durably consumes nonce uniqueness across overlapping key IDs.
- Evidence copied from a CAGE-published closed bundle into a sidecar-owned private snapshot before verification.

## Outcome contract

- `PASS`: signed receipt and exact releasable response bytes.
- `REVIEW`: signed receipt, findings, and no releasable response bytes.
- `BLOCKED`: signed receipt, findings, and no releasable response bytes.
- `RELEASE_REFUSED`: already-issued signed prospective PASS receipt, stable terminal release-refusal evidence, and no releasable response bytes.
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
