# Beginner Tutorial: From Draft to Verified Release

This tutorial shows the complete flow without requiring an external model or TypeScript knowledge. You will verify one response through the JSON CLI, call the same verifier from Python, and then inspect the TypeScript host example.

The central rule is simple: **users receive only the exact response that earned `PASS`.** `REVIEW`, `BLOCKED`, malformed input, and checker failures release nothing.

## 1. Install and verify

```bash
git clone https://github.com/SimranPabla/agent-integrity.git
cd agent-integrity
npm ci
npm run verify
```

You need Git, Node.js 22+, npm 10+, and Python 3 only for the Python step. The examples are local and require no model provider or API key. A successful `npm run verify` finishes with all tests and builds passing.

## 2. Run the language-neutral CLI example

```bash
npm run build
node packages/cli/dist/cli.js verify \
  --trusted-policy examples/cli-quickstart/integrity/policy.yaml \
  --trusted-config examples/cli-quickstart/integrity/trusted-config.json \
  < examples/cli-quickstart/request.json
```

The verifier returns JSON with `"status": "PASS"` and exits with code `0`. It independently reloads the policy, decision registry, and source file instead of trusting copies supplied in the request.

## 3. Understand the five inputs

Open `examples/cli-quickstart/`. The files divide into two trust levels:

- **Host-controlled:** `docs/maintenance.md`, `integrity/policy.yaml`, `integrity/decisions.yaml`, and `integrity/trusted-config.json`. The application owner controls what counts as an approved source, policy, and decision snapshot.
- **Agent/application-produced:** `request.json`. It contains the draft response, its factual claim, and an exact byte anchor into the source.

The verifier does not trust the source or policy copies merely because the request names them. It reloads the host-controlled files and checks that their exact bytes match the envelope.

`PASS` means these declared inputs and live bytes satisfied the deterministic policy. It does not prove the source is true or that the application supplied every relevant source.

## 4. Call the verifier from Python

```bash
python3 examples/python-cli/verify_response.py
```

The Python host checks both the process exit code and JSON status. Only then does it print the response already bound inside the verified request. This is the same pattern a Python RAG or agent service should use at its final release boundary. The example uses only Python's standard library; the verifier itself still runs on Node.js 22+.

## 5. Inspect the TypeScript SDK path

The runnable project is `examples/basic-agent/`:

- `docs/maintenance.md` is the approved source.
- `integrity/decisions.yaml` is the trusted decision snapshot.
- `index.mjs` is the host and fake-agent flow.

The policy allows only `docs/`, requires evidence for factual and recommendation claims, and blocks mutation and replay. In a real application, load it from host configuration rather than model output.

### Follow the TypeScript data flow

`index.mjs` performs these steps:

1. Create trusted context from the project root and policy.
2. Call `collectSource` to read approved bytes and calculate their digest.
3. Hash the exact evidence byte anchor used by the claim.
4. Hash the trusted decision-registry YAML.
5. Build a response with exact UTF-8 section offsets and digest.
6. Add its claim and supporting evidence link.
7. Call `verifyTrustedEnvelope`, which recollects source and registry bytes.
8. Call the release guard and print only its returned response on `PASS`.

Run it:

```bash
npm run build
node examples/basic-agent/index.mjs
```

Expected result contains:

```json
{
  "status": "PASS",
  "response": "The maintenance window begins at 09:00 UTC."
}
```

`PASS` means the supplied envelope satisfied deterministic checks and matched the trusted files at verification time. It does not mean the sentence is objectively true or that the model disclosed every relevant source or dependency.

## 6. Exercise review and blocking

```bash
node packages/cli/dist/cli.js verify --trusted-policy examples/contradictory-evidence/integrity/policy.yaml --trusted-config examples/contradictory-evidence/integrity/trusted-config.json < examples/contradictory-evidence/request.json
echo $?
node packages/cli/dist/cli.js verify --trusted-policy examples/superseded-decision/integrity/policy.yaml --trusted-config examples/superseded-decision/integrity/trusted-config.json < examples/superseded-decision/request.json
echo $?
node examples/tampered-response/index.mjs
```

Expected exit codes are `2` for the contradiction needing review and `3` for the rejected decision. The tampering example refuses changed response bytes.

## 7. Add receipts only when your workflow needs them

Generate an Ed25519 key outside the model process, protect the private key, configure trusted public keys by key ID, and issue short-lived receipts for a fixed issuer, audience, and purpose. Keep the receipt store on one protected local filesystem. Release/recheck consumes the receipt exactly once; a concurrent or repeated consumer is blocked.

Never commit private keys. Keep old public keys until all intended receipts expire, unless compromised. Test rotation and recovery before using receipts operationally.

## 8. Integrate a real model

Ask the model for a draft plus structured sections, claims, decision IDs, and evidence references. Validate that object strictly. The host—not the model—must collect sources, load policy/decisions, calculate byte digests, verify, create/consume receipts, and release the final bytes.

Before enabling release in production, test these four paths in your own host: an unchanged `PASS`, an ambiguous `REVIEW`, a definite `BLOCKED`, and a verifier crash or malformed result. Only the first path may return response bytes to the user.

Do not stream the draft. Route `REVIEW` to a human queue and treat `BLOCKED` as a failed release.
