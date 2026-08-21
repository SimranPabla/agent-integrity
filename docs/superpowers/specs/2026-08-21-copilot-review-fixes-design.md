# Copilot Review Fixes Design

## Scope

Resolve three accepted review findings without changing workflow-run selection:

1. Read the Git commit from the signed SLSA v1 provenance statement's resolved dependency and require an exact match with the release manifest.
2. Always remove the temporary npm pack directory after publish, skip, or failure.
3. Treat only known Windows directory-open errors as unsupported directory fsync; propagate every other error.

## Verification and rollback

Add focused regression tests for provenance commit extraction, missing/mismatched commits, publish cleanup, and directory-open error classification. Run the focused tests and the complete verification suite before pushing. The change is rollback-safe as one PR commit; no package is published and no release workflow or tag is changed.
