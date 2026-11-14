#!/usr/bin/env bash
set -euo pipefail
command -v rg >/dev/null 2>&1 || { printf "%s\n" "secret scanner requires rg" >&2; exit 2; }
if [[ $# -ne 1 || -z "$1" ]]; then printf "%s\n" "usage: check-sidecar-secrets.sh EXTERNAL_RUNBOOK_PATH" >&2; exit 2; fi
ROOT=$(git rev-parse --show-toplevel) || { printf "%s\n" "cannot resolve repository" >&2; exit 2; }
BASE=880ea482fce4a6ee8914f8922a8ab12cc0ba1a59
git -C "$ROOT" cat-file -e "$BASE^{commit}" || { printf "%s\n" "missing scanner base" >&2; exit 2; }
LIST=$(mktemp) || { printf "%s\n" "cannot create scanner inventory" >&2; exit 2; }
trap 'rm -f -- "$LIST"' EXIT
git -C "$ROOT" diff --name-only --diff-filter=ACMRT -z "$BASE" -- > "$LIST" || { printf "%s\n" "cannot collect scanner inventory" >&2; exit 2; }
mapfile -d '' -t RELATIVE < "$LIST"
TARGETS=()
for item in "${RELATIVE[@]}"; do TARGETS+=("$ROOT/$item"); done
TARGETS+=("$1")
for target in "${TARGETS[@]}"; do
  if [[ ! -f "$target" || ! -r "$target" ]]; then printf "unreadable scanner target: %s\n" "$target" >&2; exit 2; fi
done
# Scan material, not variable identifiers or documentation-only path references.
PATTERN='-----BEGIN (RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----|github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_-]{20,}|"(hmacSecret|privateKey|apiKey|accessToken|password)"[[:space:]]*:[[:space:]]*"[^"[:space:]][^"]*"'
if rg --files-with-matches --color never -- "$PATTERN" "${TARGETS[@]}"; then
  printf "%s\n" "secret material detected; release withheld" >&2; exit 1
else
  code=$?
  if [[ $code -ne 1 ]]; then printf "scanner/read failure (rg exit %s)\n" "$code" >&2; exit 2; fi
fi
printf "%s\n" "sidecar secret scan passed"
