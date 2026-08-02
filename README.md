# Agent Integrity

Agent Integrity is an agent-first, deterministic verification engine for developers building AI agents. It checks whether an exact agent response is consistent with the approved sources, decisions, claims, and evidence submitted for that run—and refuses to release a changed or definitively invalid response.

The agent prepares a complete response envelope. Agent Integrity, which does not call an LLM, independently calculates one outcome:

- `PASS`: deterministic checks succeeded and the exact checked response may be released.
- `REVIEW`: the response is held because human judgment is needed.
- `BLOCKED`: the response is held because a definite integrity violation or checker failure occurred.

Agent Integrity verifies consistency and tamper resistance. It does **not** prove objective truth, complete evidence, sound reasoning, safety, or correctness. Read [Limitations](docs/LIMITATIONS.md) before using it as a release boundary.

## Why use it?

Agent applications often let the same model gather evidence, interpret policy, write an answer, and declare the work complete. That creates avoidable failure modes:

- an important claim has no cited support;
- contextual evidence is presented as proof;
- a contradiction is included but hidden from the reader;
- an old, rejected decision is revived;
- a source or response changes after verification;
- a stale receipt is replayed for a different answer;
- a checker error is accidentally treated as success.

Agent Integrity makes those checks deterministic and content-bound. It is useful for research agents, policy assistants, report generators, decision-support agents, and any agent that must explain how an answer relates to approved evidence.

## Status and version

Current version: `0.1.0-alpha.0` using protocol `1-alpha`.

This is alpha software. Protocols and APIs may change before `1.0.0`. Alpha receipts are unsigned and must not be presented as third-party attestations. See [Security](SECURITY.md), [Protocol](docs/PROTOCOL.md), and [Limitations](docs/LIMITATIONS.md).

## Requirements

- Node.js 22 or newer
- npm 10 or newer
- Git, only when installing from source
- TypeScript 5.8 or newer when embedding the SDK in a TypeScript project
- A server-side Node.js runtime; browsers, edge runtimes, Deno, and Bun are not yet supported or tested

The engine is model- and provider-independent. It can sit behind any agent that can construct the documented JSON envelope or call the TypeScript SDK, including custom agents built with OpenAI, Anthropic, Google, open-source models, LangChain, Mastra, or an in-house framework. These are compatibility categories, not bundled integrations. Agent Integrity does not call those providers and does not require their SDKs.

## Install from source

The npm packages are not published yet. Use the source installation below during alpha review.

> Publication placeholder: replace `<YOUR-GITHUB-ORG>` with the final GitHub owner when the repository becomes public.

1. Install Node.js 22+ and Git.
2. Clone the repository:

   ```bash
   git clone https://github.com/<YOUR-GITHUB-ORG>/agent-integrity.git
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

5. Run the complete verification suite:

   ```bash
   npm run verify
   npm audit --audit-level=high
   ```

6. Run the basic agent example:

   ```bash
   node examples/basic-agent/index.mjs
   ```

   A successful run prints a `PASS` result and the exact released response.

7. Run the negative examples:

   ```bash
   node packages/cli/dist/cli.js verify < examples/contradictory-evidence/request.json
   node packages/cli/dist/cli.js verify < examples/superseded-decision/request.json
   node examples/tampered-response/index.mjs
   ```

   The first command exits `2` (`REVIEW`). The second exits `3` (`BLOCKED`). The tampering example shows that changed response bytes are not released.

## Package installation after publication

These commands are reserved for the first package release and do not work until the packages are published:

```bash
npm install @agent-integrity/sdk @agent-integrity/core
npm install --global @agent-integrity/cli
```

Until then, import from the built workspace packages or use the JSON CLI from a source checkout.

## Five-minute SDK integration

An integration normally performs five steps:

1. Load the project policy once.
2. Collect the exact sources and decision events used for the run.
3. Let the agent draft its response and claim-to-evidence mappings.
4. Build and verify the complete envelope.
5. Release only the unchanged response returned by the release guard.

```js
import { verifyEnvelope } from "@agent-integrity/core";
import {
  AgentIntegritySession,
  releaseVerifiedResponse,
} from "@agent-integrity/sdk";

const session = new AgentIntegritySession(parsedPolicy);

session.addSource(sourceRecord);
session.addDecision(activeDecision);
session.addEvidence(evidenceItem);
session.addClaim(claim);
session.setResponse(
  "The exact response shown to the user.",
  [{ sectionId: "recommendation", substantive: true }],
);

const envelope = session.buildEnvelope();
const verification = verifyEnvelope(envelope);
const release = releaseVerifiedResponse({ envelope, verification });

if (release.status === "PASS") {
  process.stdout.write(release.response);
} else {
  // REVIEW and BLOCKED contain findings but never release response bytes.
  sendToReviewQueue(release.verification.findings);
}
```

The complete, runnable version is in [examples/basic-agent](examples/basic-agent/README.md). See the [Integration Guide](docs/INTEGRATION_GUIDE.md) for collection boundaries, lifecycle guidance, and error handling.

## CLI

The CLI uses one JSON request on stdin and one JSON result on stdout. It does not echo source or response content.

```bash
node packages/cli/dist/cli.js <command> < request.json
```

Commands:

- `validate-policy`: parse and validate the strict YAML policy.
- `verify`: validate a complete envelope and calculate its outcome.
- `recheck`: compare a receipt with the live bound content and replay state.
- `inspect-receipt`: validate and summarize a receipt without exposing response content.

Stable exit codes:

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

- `@agent-integrity/protocol`: versioned, language-neutral data structures.
- `@agent-integrity/core`: deterministic validation, canonical hashing, outcomes, receipts, and rechecking.
- `@agent-integrity/sdk`: run-envelope construction and exact-response release guard.
- `@agent-integrity/cli`: JSON stdin/stdout interoperability for any language.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Integration Guide](docs/INTEGRATION_GUIDE.md)
- [Protocol reference](docs/PROTOCOL.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Limitations](docs/LIMITATIONS.md)
- [Examples](examples/README.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

## Development

```bash
npm ci
npm run typecheck
npm test
npm run build
npm run verify
```

Tests include unit, adversarial, package-export, and language-neutral conformance fixtures. Every protocol change should add or update a fixture so another implementation can reproduce the outcome.

## Security and license

Report vulnerabilities through the process in [SECURITY.md](SECURITY.md). Contributions are governed by [CONTRIBUTING.md](CONTRIBUTING.md). Agent Integrity is licensed under Apache-2.0; see [LICENSE](LICENSE).
