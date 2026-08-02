# Basic agent

This example shows the intended agent-first integration: the SDK constructs a
run envelope, the independent core verifies it, and the release guard returns
the exact response only on `PASS`.

Run `node examples/basic-agent/index.mjs` after `npm run build`.
