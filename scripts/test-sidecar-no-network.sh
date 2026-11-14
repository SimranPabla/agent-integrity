#!/bin/sh
# No system/network configuration changes: an invocation-owned network namespace.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
command -v unshare >/dev/null 2>&1 || { echo 'INCONCLUSIVE: unshare unavailable' >&2; exit 77; }
TMP=$(mktemp -d /tmp/ai-task10-net.XXXXXXXX)
cleanup() {
 case "$TMP" in /tmp/ai-task10-net.????????) [ -d "$TMP" ] && [ ! -L "$TMP" ] && rm -r -- "$TMP" ;; *) echo 'unsafe cleanup target' >&2; exit 1 ;; esac
 echo 'cleanup: exact owned network proof directory removed'
}
trap cleanup 0
trap 'exit 1' 1 2 15
if ! unshare --net true 2>"$TMP/preflight.stderr"; then
 cat "$TMP/preflight.stderr" >&2
 echo 'INCONCLUSIVE: network namespace capability denied' >&2
 exit 77
fi
unshare --net sh -eu -c '
 cd "$1"
 # /proc/net/dev follows the current network namespace; host sysfs may not.
 awk -F: '"'"'NR > 2 {gsub(/[[:space:]]/, "", $1); if ($1 != "lo") exit 1}'"'"' /proc/net/dev || { echo "unexpected external interface" >&2; exit 1; }
 cat /proc/net/dev
 echo "isolated network namespace: loopback only"
 exec node node_modules/vitest/vitest.mjs run packages/sidecar/tests/e2e.test.ts --maxWorkers=1 --no-file-parallelism
' sh "$ROOT"
