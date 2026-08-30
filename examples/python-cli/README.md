# Python CLI Integration

This example shows the smallest safe Python host pattern. Python starts the language-neutral verifier as a subprocess, checks both its exit code and JSON status, and releases the exact bound response only for `PASS`.

No Python package is required, but the verifier still requires Node.js 22+ because Python calls the Node CLI. Build the repository once, then run:

```bash
npm ci
npm run build
python3 examples/python-cli/verify_response.py
```

Expected output:

```text
The maintenance window begins at 09:00 UTC.
```

The script fails closed: `REVIEW`, `BLOCKED`, malformed verifier output, and subprocess failures release no response.

In a real application, replace the checked-in `request.json` with an envelope assembled from your agent draft and host-observed retrieval data. Keep policy, approved source roots, and the decision registry under host control. Do not let the model replace them.

See the [CLI quick start](../cli-quickstart/README.md) to understand each input, then use the [integration guide](../../docs/INTEGRATION_GUIDE.md) for production boundaries.
