# Public release runbook

The repository and packages are engineered for a public alpha release, but publication remains a manual maintainer decision.

Before changing repository visibility:

1. Protect `main`; require pull requests, passing checks, and review.
2. Create the `npm-release` GitHub environment and require maintainer approval.
3. Enable GitHub private vulnerability reporting.
4. Configure npm trusted publishing for this repository and workflow for all four scoped packages.
5. Confirm the `@agent-integrity` npm scope is controlled by the maintainer.
6. Run `npm ci`, `npm run verify`, `npm run pack:check`, `npm audit --audit-level=high`, and `npm run release:check` from a clean checkout.
7. Inspect the exact tag commit, then create `v<package-version>`. Do not run `npm publish` manually.

The tag workflow uses SHA-pinned actions, the protected `npm-release` environment, npm OIDC provenance, exact version/tag matching, and ordered publication. Each package step is idempotent: it skips an existing version only when the registry tarball integrity exactly matches the local tarball, allowing safe recovery after a partial multi-package publish. A mismatch fails closed.

Rollback cannot delete an npm version. Deprecate a bad version, publish a forward fix with a new version, and document it in the changelog. Never move or recreate a published tag.
