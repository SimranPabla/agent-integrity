# @agent-integrity/sdk

Session construction and exact-response release controls for Node.js agent hosts.

```js
import { AgentIntegritySession, releaseVerifiedResponse } from "@agent-integrity/sdk";
```

The plain `releaseVerifiedResponse` guard synchronously selects its envelope, supplied verification and context through own enumerable data descriptors, then captures each before any await. Every check uses the captured input, and PASS returns only the captured response string. Later replacement or mutation of caller options cannot change released bytes. Capture failures, REVIEW, BLOCKED and verification errors return no response. Caller data is not mutated or frozen.

Use the descriptor-safe JSON domain documented in the core README: ordinary dense arrays and plain/null-prototype records, including frozen data, with no accessors, hidden/symbol/extra array properties, unsupported values or cycles. Only absent/undefined optional context byte ceilings are omitted. Dense JSON hashes stay unchanged. The guard selects only its three plain fields rather than copying signed-only Date/store capabilities. This does **not** fix the signed outer transaction in `releaseVerifiedReceipt` or receipt creation/rechecking/store callbacks; those remain unresolved. Hostile Proxy traps are not guaranteed side-effect-free.

Buffer drafts until verification finishes. Release only the `response` returned by a `PASS` release result. Do not stream model output around this boundary. See the [basic agent example](../../examples/basic-agent/README.md) for runnable code.
