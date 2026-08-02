# @agent-integrity/cli

JSON stdin/stdout access to Agent Integrity for non-TypeScript hosts.

```bash
integrity validate-policy < request.json
integrity verify < request.json
integrity recheck < request.json
integrity inspect-receipt < receipt.json
```

Exit codes in the current alpha are `0` for success/PASS, `2` for REVIEW, `3` for BLOCKED, and `1` for invalid input or command failure. See the Integration Guide for complete request objects.
