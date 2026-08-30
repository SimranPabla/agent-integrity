"""Call Agent Integrity from Python and release only an exact PASS response."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
REQUEST_PATH = REPO_ROOT / "examples" / "cli-quickstart" / "request.json"
POLICY_PATH = REPO_ROOT / "examples" / "cli-quickstart" / "integrity" / "policy.yaml"
CONFIG_PATH = REPO_ROOT / "examples" / "cli-quickstart" / "integrity" / "trusted-config.json"
CLI_PATH = REPO_ROOT / "packages" / "cli" / "dist" / "cli.js"


def verify() -> str | None:
    request = json.loads(REQUEST_PATH.read_text(encoding="utf-8"))
    completed = subprocess.run(
        [
            "node",
            str(CLI_PATH),
            "verify",
            "--trusted-policy",
            str(POLICY_PATH),
            "--trusted-config",
            str(CONFIG_PATH),
        ],
        cwd=REPO_ROOT,
        input=json.dumps(request),
        text=True,
        capture_output=True,
        check=False,
    )

    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError:
        print("Verifier failed without a valid JSON result; response held.", file=sys.stderr)
        return None

    status = result.get("status")
    if completed.returncode == 0 and status == "PASS":
        return request["envelope"]["response"]["content"]
    if completed.returncode == 2 and status == "REVIEW":
        print("Human review required; response held.", file=sys.stderr)
    elif completed.returncode == 3 and status == "BLOCKED":
        print("Integrity check blocked release; response held.", file=sys.stderr)
    else:
        print("Verifier error or inconsistent result; response held.", file=sys.stderr)
    return None


if __name__ == "__main__":
    verified_response = verify()
    if verified_response is None:
        raise SystemExit(1)
    print(verified_response)
