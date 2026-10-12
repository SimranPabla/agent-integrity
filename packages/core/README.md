# @agent-integrity/core

Deterministic verification, trusted filesystem/decision collection, canonical hashing, and Ed25519 receipt operations.

Use `verifyTrustedEnvelope` for release decisions. The lower-level structural verifier does not recollect sources or load the trusted decision registry and must not be used as a release boundary.

Plain trusted verification captures the envelope and context synchronously before its first await. Checks and the returned digest use those private copies; caller objects are neither changed nor frozen. Live source recollection is still required: copying inputs does not snapshot files or make mutable source trees race-free.

The additive `captureJsonData` and `captureTrustedContext` exports support the SDK plain guard. Their stricter JavaScript admission domain is JSON primitives, plain records (Object.prototype or null prototype), and ordinary dense arrays with own enumerable data fields. Frozen data is accepted. Accessors (including hidden ones), hidden/symbol properties, dangerous record keys, holes/inherited indices, custom prototypes/subclasses, extra array properties (including custom map), nonfinite numbers, unsupported values, and cycles are rejected without invoking caller getters, toJSON, iterators, or methods. Shared noncyclic references are copied as separate occurrences. Only root context maxSourceBytes/maxTotalSourceBytes may be absent or undefined; explicit undefined elsewhere is rejected, not normalized away. Array length is the sole permitted non-enumerable structural property, including frozen length.

Limits match canonical JSON per captured root: container depth 64 (root depth zero), 100,000 container occurrences, and 16 MiB UTF-8 per string. Envelope, verification and context do not share a wrapper budget. Supported dense JSON canonical bytes remain unchanged. Capture remains stricter than the exported canonical helpers described below. Descriptor/prototype inspection can invoke hostile Proxy traps; this is not Proxy detection or a zero-side-effect guarantee.

Plain verification capture covers direct verifyTrustedEnvelope and the plain SDK guard. Receipt recheck separately captures only its own receipt data property synchronously, asserts the unchanged closed 2-alpha schema, and uses that private receipt in both checks and trusted consumption. Missing/accessor receipt properties and malformed receipt JSON return BLOCKED checker.failure without digests or consumption. Schema string lengths count Unicode code points; date-time admission matches the full format oracle and does not replace later timestamp semantics. Signature syntax admission remains separate from canonical decoded-byte validation.

This is receipt-only ownership, not coherent signed outer-transaction capture: envelope/context/trust/Date/store capability behavior outside that receipt remains unchanged. releaseVerifiedReceipt, createReceipt, safe callback ownership, freshness at consume and release-output repair remain outside this change. No caller data is mutated or frozen, and hostile Proxy traps remain outside the side-effect-free claim. Existing malformed issued records are retained but refused without consumption; rollback must not rewind consumed markers or automatically reissue receipts.

## Canonical helpers and JavaScript inputs

The exported `canonicalJson` and `sha256Canonical` helpers traverse arrays using one captured own length data descriptor (integer uint32, non-enumerable, non-configurable; either writable flag), then each required own data-index descriptor. Holes, inherited required indices and own index accessors now throw TypeError at the indexed path without invoking index accessors. Caller map output is no longer honored; map, join, constructor/species, toJSON and iterator hooks are not accessed. Caller inputs are not cloned, frozen or mutated.

Dense subclasses and custom-prototype arrays, frozen arrays and non-enumerable/non-writable data indices remain supported. Dense null-prototype arrays are accepted additively. Unrelated string/symbol array properties are ignored without reading their values, including accessor extras. This intentionally lossy projection is not closed JavaScript admission or a new collision-resistance guarantee; previously accepted non-JSON projections may change or reject. Supported dense JSON canonical bytes/digests remain unchanged. The record domain remains plain/null-prototype records with sorted enumerable own string keys: dangerous keys, accessors and undefined values reject; hidden and symbol properties remain ignored. Unsupported values, nonfinite numbers and cycles still reject; shared noncyclic containers are counted separately per occurrence.

Limits remain container depth 64 (root zero), 100,000 container occurrences and 16 MiB UTF-8 per string. Primitives do not consume the container count or container-depth checks. There is no per-array, primitive-node, key-byte or aggregate transport budget; very large dense arrays can still consume substantial time/memory. Internal push/join use trusted host intrinsics. Hostile Proxy traps, globally modified intrinsics/prototypes and concurrent hostile mutation are outside side-effect-free guarantees; no Proxy detection or hardened-realm claim is made.

This helper repair does not loosen the stricter capture admission or fix signed outer-transaction ownership. No schema, hash algorithm/version or receipt migration is introduced, nor is valid-envelope/signature forgery established. Reverting restores known unsafe sparse/hook behavior, not a security recovery; halt dependent untrusted use rather than treating revert as recovery. Rejected/non-JSON inputs are not automatically migrated or reissued.

The trusted context must include `trustedPolicy`, parsed from host-controlled configuration independently of the envelope. Verification rejects any embedded policy mismatch or downgrade.

```js
import { collectSource, verifyTrustedEnvelope } from "@agent-integrity/core";
```

Requires Node.js 22+. See the [Integration Guide](../../docs/INTEGRATION_GUIDE.md) for the full trusted context and key-management flow.
