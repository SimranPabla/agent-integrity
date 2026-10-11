# @agent-integrity/core

Deterministic verification, trusted filesystem/decision collection, canonical hashing, and Ed25519 receipt operations.

Use `verifyTrustedEnvelope` for release decisions. The lower-level structural verifier does not recollect sources or load the trusted decision registry and must not be used as a release boundary.

Plain trusted verification captures the envelope and context synchronously before its first await. Checks and the returned digest use those private copies; caller objects are neither changed nor frozen. Live source recollection is still required: copying inputs does not snapshot files or make mutable source trees race-free.

The additive `captureJsonData` and `captureTrustedContext` exports support the SDK plain guard. Their stricter JavaScript admission domain is JSON primitives, plain records (Object.prototype or null prototype), and ordinary dense arrays with own enumerable data fields. Frozen data is accepted. Accessors (including hidden ones), hidden/symbol properties, dangerous record keys, holes/inherited indices, custom prototypes/subclasses, extra array properties (including custom map), nonfinite numbers, unsupported values, and cycles are rejected without invoking caller getters, toJSON, iterators, or methods. Shared noncyclic references are copied as separate occurrences. Only root context maxSourceBytes/maxTotalSourceBytes may be absent or undefined; explicit undefined elsewhere is rejected, not normalized away. Array length is the sole permitted non-enumerable structural property, including frozen length.

Limits match canonical JSON per captured root: container depth 64 (root depth zero), 100,000 container occurrences, and 16 MiB UTF-8 per string. Envelope, verification and context do not share a wrapper budget. Supported dense JSON canonical bytes and the exported canonicalJson behavior are unchanged. Descriptor/prototype inspection can invoke hostile Proxy traps; this is not Proxy detection or a zero-side-effect guarantee.

This capture repair covers direct verifyTrustedEnvelope and the plain SDK guard only. It does not repair signed outer transactions in releaseVerifiedReceipt, createReceipt, recheckTrustedReceipt, or store callbacks; consistent signed-transaction capture remains unresolved.

The trusted context must include `trustedPolicy`, parsed from host-controlled configuration independently of the envelope. Verification rejects any embedded policy mismatch or downgrade.

```js
import { collectSource, verifyTrustedEnvelope } from "@agent-integrity/core";
```

Requires Node.js 22+. See the [Integration Guide](../../docs/INTEGRATION_GUIDE.md) for the full trusted context and key-management flow.
