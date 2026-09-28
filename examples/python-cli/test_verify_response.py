"""Fail-closed unit tests for the standard-library Python integration example."""

from __future__ import annotations

import json
import unittest
from contextlib import redirect_stderr
from io import StringIO
from subprocess import CompletedProcess
from unittest.mock import patch

import verify_response


def completed(returncode: int, payload: object) -> CompletedProcess[str]:
    stdout = payload if isinstance(payload, str) else json.dumps(payload)
    return CompletedProcess(args=["node"], returncode=returncode, stdout=stdout, stderr="")


def verify_with_stderr() -> tuple[str | None, str]:
    stderr = StringIO()
    with redirect_stderr(stderr):
        result = verify_response.verify()
    return result, stderr.getvalue()


class VerifyResponseTests(unittest.TestCase):
    @patch("verify_response.subprocess.run")
    def test_releases_only_a_pass_from_a_successful_process(self, run) -> None:
        run.return_value = completed(0, {"status": "PASS"})

        result = verify_response.verify()

        request = json.loads(verify_response.REQUEST_PATH.read_text(encoding="utf-8"))
        self.assertEqual(result, request["envelope"]["response"]["content"])
        self.assertFalse(run.call_args.kwargs["check"])

    @patch("verify_response.subprocess.run")
    def test_holds_review(self, run) -> None:
        run.return_value = completed(2, {"status": "REVIEW"})

        result, stderr = verify_with_stderr()
        self.assertIsNone(result)
        self.assertIn("Human review required", stderr)

    @patch("verify_response.subprocess.run")
    def test_holds_blocked(self, run) -> None:
        run.return_value = completed(3, {"status": "BLOCKED"})

        result, stderr = verify_with_stderr()
        self.assertIsNone(result)
        self.assertIn("blocked release", stderr)

    @patch("verify_response.subprocess.run")
    def test_holds_malformed_verifier_output(self, run) -> None:
        run.return_value = completed(1, "not-json")

        result, stderr = verify_with_stderr()
        self.assertIsNone(result)
        self.assertIn("without a valid JSON result", stderr)

    @patch("verify_response.subprocess.run")
    def test_holds_inconsistent_pass_with_error_exit(self, run) -> None:
        run.return_value = completed(1, {"status": "PASS"})

        result, stderr = verify_with_stderr()
        self.assertIsNone(result)
        self.assertIn("Verifier error or inconsistent result", stderr)


if __name__ == "__main__":
    unittest.main()
