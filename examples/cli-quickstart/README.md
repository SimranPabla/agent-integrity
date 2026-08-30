# CLI Quick Start

This example answers one question: **may this exact response be released based on the approved source?**

The example contains five inputs. Four are controlled by the trusted application host; one is produced for the individual agent run:

- **Host-controlled** `docs/maintenance.md`: the approved source file;
- **Host-controlled** `integrity/policy.yaml`: the rules the verifier must enforce;
- **Host-controlled** `integrity/decisions.yaml`: the current trusted decision snapshot (empty here);
- **Host-controlled** `integrity/trusted-config.json`: paths the agent cannot replace;
- **Per response** `request.json`: the draft response and its declared claim-to-evidence mapping.

From the repository root, build and verify it:

```bash
npm ci
npm run build
node packages/cli/dist/cli.js verify \
  --trusted-policy examples/cli-quickstart/integrity/policy.yaml \
  --trusted-config examples/cli-quickstart/integrity/trusted-config.json \
  < examples/cli-quickstart/request.json
```

Expected result:

```json
{
  "status": "PASS",
  "findings": []
}
```

The command exits `0`. `PASS` means the exact response, declared evidence, live source bytes, policy, and decision snapshot passed the configured deterministic checks. It does not prove that the source is true or that the application supplied every relevant source.

In plain language, the response says the window starts at `09:00 UTC`; its factual claim points to the matching bytes in the approved source; and the verifier confirms that neither the source, mapping, policy, nor response changed.

## See a failure

Change `09:00` to `10:00` in `request.json` without updating its hashes. Run the same command again. The verifier returns `BLOCKED` because the response no longer matches the bytes that were checked. This demonstrates tamper detection; it is not a semantic fact-check.

Restore the file before continuing:

```bash
git restore examples/cli-quickstart/request.json
```

Next, run the same verification from [Python](../python-cli/README.md), or read the [integration guide](../../docs/INTEGRATION_GUIDE.md).
