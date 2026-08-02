# Tampered response

Run `node examples/tampered-response/index.mjs` after building. The example
verifies one response, changes its bytes, and proves the release guard returns
`BLOCKED` without releasing the changed response.
