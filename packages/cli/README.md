# @agent-integrity/cli

JSON stdin/stdout access to Agent Integrity for non-TypeScript hosts.

```bash
integrity validate-policy < request.json
integrity verify --trusted-policy /absolute/path/policy.yaml < request.json
integrity recheck --trusted-policy /absolute/path/policy.yaml < request.json
integrity inspect-receipt < receipt.json
```

Exit codes in the current alpha are `0` for success/PASS, `2` for REVIEW, `3` for BLOCKED, and `1` for invalid input or command failure. See the Integration Guide for complete request objects.

`verify` and `recheck` never trust the envelope policy supplied on stdin. They require a separately loaded policy file. Stdin and trusted-policy files are each limited to 1 MiB. `inspect-receipt` compares the receipt self-digest only; it does not verify the Ed25519 signature or establish receipt validity.
