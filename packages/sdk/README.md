# @agent-integrity/sdk

Session construction and exact-response release controls for Node.js agent hosts.

```js
import { AgentIntegritySession, releaseVerifiedResponse } from "@agent-integrity/sdk";
```

The plain `releaseVerifiedResponse` guard synchronously selects its envelope, supplied verification and context through own enumerable data descriptors, then captures each before any await. Every check uses the captured input, and PASS returns only the captured response string. Later replacement or mutation of caller options cannot change released bytes. Capture failures, REVIEW, BLOCKED and verification errors return no response. Caller data is not mutated or frozen.

Use the descriptor-safe JSON domain documented in the core README: ordinary dense arrays and plain/null-prototype records, including frozen data, with no accessors, hidden/symbol/extra array properties, unsupported values or cycles. Only absent/undefined optional context byte ceilings are omitted. Dense JSON hashes stay unchanged. The plain guard selects only its three plain fields rather than copying signed-only Date/store capabilities. Hostile Proxy traps are not guaranteed side-effect-free.

The signed `releaseVerifiedReceipt` guard synchronously selects all seven outer fields through own enumerable data descriptors before any await. It privately captures the envelope, supplied verification, context, receipt and trust data, copies `now` using the Date intrinsic, and retains one selected receipt-store reference. Both verification stages, receipt consumption and the returned response use this same transaction. Replacing outer fields or mutating caller-owned plain data/Date after invocation cannot retarget the receipt or released response. Explicitly undefined `maxClockSkewMs`, `maxLifetimeMs` and `revokedKeyIds` trust fields retain their default/absent behavior; other unsupported data fails closed. Capture, verification and consumption failures return no response.

The selected store is a trusted host capability, not cloned or frozen: the host must keep its methods, internal state and protected directory stable. This guard does not sandbox a malicious store/host, make multi-file reads atomic, guarantee time freshness at eventual delivery, or repair the separate core receipt-creation/recheck/store entrypoints. It does not prove semantic truth, complete evidence, action authorization or downstream exactly-once delivery. The host must dispatch the returned response itself without alteration.

Buffer drafts until verification finishes. Release only the `response` returned by a `PASS` release result. Do not stream model output around this boundary. See the [basic agent example](../../examples/basic-agent/README.md) for runnable code.
