# Agent Integrity

AI agents can produce convincing answers that cite the wrong passage, rely on an outdated decision, or change after review. Agent Integrity is an open-source release gate that lets your application check an exact response against approved source bytes, policy, and decisions **before a user receives it**.

It does not call another LLM. Your agent drafts the answer and declares its claims and evidence; the deterministic verifier decides whether those exact bytes may be released.

```text
agent draft → claims + evidence → deterministic check → PASS / REVIEW / BLOCKED
                                                        ↓
                                              release, hold, or stop
```

The agent prepares a complete response envelope. Agent Integrity, which does not call an LLM, independently calculates one outcome:

- `PASS`: the submitted envelope satisfied the configured deterministic checks and the exact checked response may be released. It does not prove semantic truth, evidence completeness, or that the application classified every dependency correctly.
- `REVIEW`: the response is held because human judgment is needed.
- `BLOCKED`: the response is held because a definite integrity violation or checker failure occurred.

Agent Integrity verifies consistency and tamper resistance. It does **not** prove objective truth, complete evidence, sound reasoning, safety, or correctness. Read [Limitations](docs/LIMITATIONS.md) before using it as a release boundary.

## Is this for you?

- **AI and backend developers:** gate source-grounded RAG answers, reports, or recommendations before release.
- **Python developers:** use the language-neutral JSON CLI as a subprocess; no Python SDK is required.
- **Node.js developers:** use the TypeScript SDK for in-process envelope construction and release control.
- **Platform and DevOps engineers:** enforce exit-code-based release behavior in a service or pipeline.
- **Security and governance teams:** inspect the threat model, deterministic findings, and signed receipt boundaries.

Agent Integrity verifies responses. It is not a tool-execution sandbox or an authorization system for consequential actions.

Start here if your application produces a response that must stay tied to approved evidence or a current decision. If you only need ordinary citation display, logging, or model evaluation, this project may be more machinery than you need.

## Why use it?

Agent applications often let the same model gather evidence, interpret policy, write an answer, and declare the work complete. That creates avoidable failure modes:

- an important claim has no cited support;
- contextual evidence is presented as proof;
- a contradiction is included but hidden from the reader;
- a declared claim reference points to an unknown, rejected, or superseded decision;
- a source or response changes after verification;
- a stale receipt is replayed for a different answer;
- a checker error is accidentally treated as success.

Agent Integrity makes those checks deterministic and content-bound. It is useful for research agents, policy assistants, report generators, decision-support agents, and any agent that must explain how an answer relates to approved evidence.

Decision assurance is limited to the current trusted YAML snapshot. The verifier checks event order and lifecycle inside that snapshot but consults no prior-run checkpoint, so cross-run history preservation depends on trusted host storage. It validates only the `decisionIds` declared on each claim and cannot infer an omitted semantic dependency.

## Status and version

Current version: `0.1.0-alpha.2` using protocol `1-alpha`.

This is alpha software. Protocols and APIs may change before `1.0.0`. Receipt `2-alpha` uses Ed25519 producer authentication and a local filesystem registry for atomic single-use consumption. The registry must remain on one host filesystem and be protected from untrusted modification. See [Security](SECURITY.md), [Protocol](docs/PROTOCOL.md), and [Limitations](docs/LIMITATIONS.md).

## Requirements

- Node.js 22 or newer
- npm 10 or newer
- Git, only when installing from source
- TypeScript 5.8 or newer when embedding the SDK in a TypeScript project
- A server-side Node.js runtime; browsers, edge runtimes, Deno, and Bun are not yet supported or tested

The engine is provider-independent by design. No named model provider or agent framework is bundled or tested in `0.1.0-alpha.2`. Any host that can construct the documented JSON envelope or call the TypeScript SDK may integrate experimentally. See the tested [compatibility matrix](docs/COMPATIBILITY.md).

## Quick start: verify one response

The npm packages are not published yet. Use the source installation below during alpha review. The example is synthetic, local, and requires no API key.

1. Install Node.js 22+ and Git.
2. Clone the repository:

   ```bash
   git clone https://github.com/SimranPabla/agent-integrity.git
   cd agent-integrity
   ```

3. Install the locked dependencies:

   ```bash
   npm ci
   ```

4. Build all packages:

   ```bash
   npm run build
   ```

5. Verify the included CLI example:

   ```bash
   node packages/cli/dist/cli.js verify \
     --trusted-policy examples/cli-quickstart/integrity/policy.yaml \
     --trusted-config examples/cli-quickstart/integrity/trusted-config.json \
     < examples/cli-quickstart/request.json
   ```

   Expected: exit code `0`, status `PASS`, and no findings.

6. Run the same flow from Python:

   ```bash
   python3 examples/python-cli/verify_response.py
   ```

   Expected: the exact verified response is printed. All non-`PASS` paths release nothing.

7. Run the repository checks and negative examples:

   ```bash
   npm run verify
   npm audit --audit-level=high
   node packages/cli/dist/cli.js verify --trusted-policy examples/contradictory-evidence/integrity/policy.yaml --trusted-config examples/contradictory-evidence/integrity/trusted-config.json < examples/contradictory-evidence/request.json
   node packages/cli/dist/cli.js verify --trusted-policy examples/superseded-decision/integrity/policy.yaml --trusted-config examples/superseded-decision/integrity/trusted-config.json < examples/superseded-decision/request.json
   node examples/tampered-response/index.mjs
   ```

   The contradiction exits `2` (`REVIEW`). The superseded decision exits `3` (`BLOCKED`). The tampering example shows that changed response bytes are not released.

The quick-start files are explained in [examples/cli-quickstart](examples/cli-quickstart/README.md). Continue with the [beginner tutorial](docs/TUTORIAL.md), then choose the [Python CLI or TypeScript SDK integration path](docs/INTEGRATION_GUIDE.md).

## Package installation after publication

These commands are reserved for the first package release and do not work until the packages are published:

```bash
npm install @agent-integrity/sdk @agent-integrity/core
npm install --global @agent-integrity/cli
```

Until then, import from the built workspace packages or use the JSON CLI from a source checkout.

## TypeScript SDK integration outline

An integration normally performs five steps:

1. Load the project policy once.
2. Load the configured decision registry and bind its exact YAML digest and complete event snapshot.
3. Let the agent draft its response and claim-to-evidence mappings.
4. Build and verify the complete envelope.
5. Release only the unchanged response returned by the release guard.

```js
import { createHash } from "node:crypto";
import { collectSource, verifyTrustedEnvelope } from "@agent-integrity/core";
import {
  AgentIntegritySession,
  releaseVerifiedResponse,
} from "@agent-integrity/sdk";

const session = new AgentIntegritySession(parsedPolicy, decisionRegistryDigest);

session.addSource(sourceRecord);
session.addDecision(activeDecision);
session.addEvidence(evidenceItem);
session.addClaim(claim);
const responseContent = "The exact response shown to the user.";
session.setResponse(
  responseContent,
  [{
    sectionId: "recommendation",
    substantive: true,
    byteStart: 0,
    byteEnd: Buffer.byteLength(responseContent, "utf8"),
    sha256: createHash("sha256").update(responseContent, "utf8").digest("hex"),
  }],
);

const context = {
  projectRoot: process.cwd(),
  allowedRoots: parsedPolicy.sources.allowedRoots,
  decisionRegistryPath: parsedPolicy.decisions.path,
  trustedPolicy: parsedPolicy,
};
// sourceRecord must come from collectSource(context + sourcePath), and each
// evidence item must include an exact byte anchor into that collected file.
const envelope = session.buildEnvelope();
const verification = await verifyTrustedEnvelope(envelope, context);
const release = await releaseVerifiedResponse({ envelope, verification, context });

if (release.status === "PASS") {
  process.stdout.write(release.response);
} else {
  // REVIEW and BLOCKED contain findings but never release response bytes.
  sendToReviewQueue(release.verification.findings);
}
```

The snippet above is an architectural outline, not copy-paste code. Follow the complete [15-minute tutorial](docs/TUTORIAL.md) or run [examples/basic-agent](examples/basic-agent/README.md). See the [Integration Guide](docs/INTEGRATION_GUIDE.md) for collection boundaries, receipt signing, lifecycle guidance, and error handling.

## CLI

The CLI uses one JSON request on stdin and one JSON result on stdout. It does not echo source or response content.

```bash
node packages/cli/dist/cli.js <command> --trusted-policy integrity/policy.yaml --trusted-config /etc/agent-integrity/trusted-config.json < request.json
```

Commands:

- `validate-policy`: parse and validate the strict YAML policy.
- `verify`: load a separately trusted policy file, validate the envelope against it, and recollect every source.
- `recheck`: load a separately trusted policy file, authenticate a receipt, and recollect source bytes.
- `inspect-receipt`: summarize fields and compare the public self-digest; it does not authenticate the producer.

`verify` and `recheck` require `--trusted-policy <path>` and `--trusted-config <path>`. The config—not stdin—controls project roots, keys, receipt expectations, and receipt-store location. Recheck uses the host system clock. Each input is limited to 1 MiB.

Current alpha exit codes:

- `0`: command succeeded or verification returned `PASS`
- `2`: verification returned `REVIEW`
- `3`: verification returned `BLOCKED`
- `1`: invalid command, malformed request, or CLI failure

Policy validation example:

```bash
printf '%s' '{"policy":"version: 1\nsources:\n  allowedRoots: [docs/]\ndecisions:\n  path: integrity/decisions.yaml\nrules:\n  requireEvidenceFor: [factual]\n  contradictions: review\n  rejectedDecisions: block\n  responseMutation: block\n  replay: block\n"}' \
  | node packages/cli/dist/cli.js validate-policy
```

See [CLI usage in the Integration Guide](docs/INTEGRATION_GUIDE.md#using-the-cli-from-any-language) and [all examples](examples/README.md).

## Repository packages

- `@agent-integrity/protocol`: versioned TypeScript data structures and a JSON interchange format.
- `@agent-integrity/core`: deterministic validation, canonical hashing, outcomes, receipts, and rechecking.
- `@agent-integrity/sdk`: run-envelope construction and exact-response release guard.
- `@agent-integrity/cli`: JSON stdin/stdout interoperability for any language.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Beginner tutorial](docs/TUTORIAL.md)
- [Integration Guide: CLI, Python, and TypeScript](docs/INTEGRATION_GUIDE.md)
- [Protocol reference](docs/PROTOCOL.md)
- [JSON Schemas](schemas/)
- [Compatibility](docs/COMPATIBILITY.md)
- [Migration policy](docs/MIGRATING.md)
- [Safe baseline policy](docs/SAFE_BASELINE_POLICY.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Limitations](docs/LIMITATIONS.md)
- [Examples](examples/README.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)
- [Governance](GOVERNANCE.md)
- [Public release runbook](docs/RELEASE.md)
- [Release-status manifest template](docs/release-status-manifest.example.json)

## Development

```bash
npm ci
npm run typecheck
npm test
npm run build
npm run verify
```

Tests include unit, adversarial, package-export, and JSON conformance fixtures. Every protocol change should add or update a fixture so another implementation can reproduce the outcome.

## Security and license

Report vulnerabilities through the process in [SECURITY.md](SECURITY.md). Contributions are governed by [CONTRIBUTING.md](CONTRIBUTING.md). Agent Integrity is licensed under Apache-2.0; see [LICENSE](LICENSE).
