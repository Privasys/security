#!/usr/bin/env bash
# Applies each patch under models/ to a fresh copy of the researchers' proposal/
# folder (pinned git submodule intra-handshake.fail), runs ProVerif, and compares
# the relay-query summary (G1, G2, G3) with models/<name>/expected.txt.
# Usage: ./run.sh [proverif-binary] [model-name ...]
set -euo pipefail
cd "$(dirname "$0")"
PV="${1:-proverif}"; shift || true
UP=intra-handshake.fail/proposal
[ -f "$UP/tls-lib-simple.pvl" ] || { echo "submodule missing: git submodule update --init"; exit 2; }
names=("$@"); [ ${#names[@]} -eq 0 ] && names=(models/*/)
fail=0
for d in "${names[@]}"; do
  d="${d%/}"; d="${d#models/}"; w="work/$d"
  echo "== $d"
  rm -rf "$w"; mkdir -p "$w"
  cp "$UP/tls-lib-simple.pvl" "$UP/tls13-multiagent.pv" "$w/"
  sed -i 's/\r$//' "$w/tls-lib-simple.pvl" "$w/tls13-multiagent.pv"   # tolerate a CRLF checkout
  patch -s "$w/tls-lib-simple.pvl" < "models/$d/changes.patch"
  ( cd "$w" && "$PV" -lib tls-lib-simple.pvl tls13-multiagent.pv > log.txt 2>&1 ) || true
  sed -n '/Verification summary/,$p' "$w/log.txt" | grep '^Query' | grep 'StateEv' \
    | grep -v '^Query not' | sed 's/^Query //' > "$w/summary.txt"
  if diff -q "models/$d/expected.txt" "$w/summary.txt" >/dev/null; then
    echo "   OK: $(wc -l < "$w/summary.txt") relay queries match expected.txt"
  else
    echo "   MISMATCH:"; diff "models/$d/expected.txt" "$w/summary.txt" || true; fail=1
  fi
done
exit $fail
