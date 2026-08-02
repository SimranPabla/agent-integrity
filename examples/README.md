# Examples

These examples contain synthetic data only. Build the repository first:

```bash
npm run build
node examples/basic-agent/index.mjs
```

The other directories contain JSON requests that can be sent to the CLI:

```bash
node packages/cli/dist/cli.js verify < examples/contradictory-evidence/request.json
```

Expected CLI exit codes are documented in each example README.
