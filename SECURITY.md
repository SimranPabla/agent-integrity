# Security Policy

## Supported versions

This project is pre-release software. Only the latest published prerelease will
receive security fixes once public releases begin.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub private
vulnerability reporting once the public repository enables it. Until then,
report privately to the repository owner through a channel listed on their
verified GitHub profile. Do not include credentials, private source documents,
or production verification envelopes in a report.

Include the affected version, reproducible steps using synthetic data, impact,
and any suggested remediation. Receipt forgery, verification bypass,
canonicalization differences, path-boundary escapes, and release of a held
response are in scope.

## Alpha warning

`1-alpha` receipts are unsigned. They detect mutation but do not authenticate a
producer. See `docs/LIMITATIONS.md` before using the project for a security
boundary.
