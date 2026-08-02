# Examples

The examples demonstrate the supported success and failure paths with synthetic data. They are designed to be read, run, modified, and used as integration tests.

## Prerequisites

From the repository root:

```bash
npm ci
npm run build
```

## Example index

### Basic agent: `PASS`

Shows an agent-first TypeScript integration. The SDK builds the envelope, the core verifies it, and the release guard returns the exact response.

```bash
node examples/basic-agent/index.mjs
```

Expected: exit `0`, status `PASS`, and a released response.

### Contradictory evidence: `REVIEW`

Shows a contradiction that exists in the submitted evidence but is not disclosed in the response. Policy routes it to human review.

```bash
node packages/cli/dist/cli.js verify < examples/contradictory-evidence/request.json
echo $?
```

Expected: exit `2`, status `REVIEW`, and no response content in CLI output.

### Superseded decision: `BLOCKED`

Shows a claim relying on a decision that has been replaced.

```bash
node packages/cli/dist/cli.js verify < examples/superseded-decision/request.json
echo $?
```

Expected: exit `3`, status `BLOCKED`, with a stale-decision finding.

### Tampered response: `BLOCKED`

Verifies a response, changes its bytes, and calls the release guard.

```bash
node examples/tampered-response/index.mjs
```

Expected: no changed response is released.

## How to experiment safely

Copy an example directory and change one field at a time:

- remove supporting evidence;
- change supporting evidence to contextual;
- mark another response section substantive without adding a claim;
- add a contradictory evidence item;
- change one response character after verification;
- change a source digest;
- advance the receipt time past expiry;
- reuse a run identifier.

Run `npm test` after modifications. Keep fixtures synthetic and never paste confidential sources or production responses into the repository.

## Building your own example

Start with `basic-agent` for an in-process TypeScript host. Start with a CLI request when integrating another language. Your example should document:

1. the failure mode or workflow it represents;
2. all prerequisites and commands;
3. expected status and exit code;
4. whether response bytes should be released;
5. what to change to observe a different outcome;
6. the relevant limitation or security assumption.

See [Integration Guide](../docs/INTEGRATION_GUIDE.md) for a production-oriented checklist.
