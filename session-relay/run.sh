#!/usr/bin/env bash
# Runs each model under models/ with ProVerif and compares the verification summary
# with models/<name>/expected.txt.
# Usage: ./run.sh [proverif-binary] [model-name ...]
set -euo pipefail
cd "$(dirname "$0")"
PV="${1:-proverif}"; shift || true
names=("$@"); [ ${#names[@]} -eq 0 ] && names=(models/*/)
fail=0
for d in "${names[@]}"; do
  d="${d%/}"; d="${d#models/}"; w="work/$d"
  echo "== $d"
  rm -rf "$w"; mkdir -p "$w"
  cp "models/$d/model.pv" "$w/"
  sed -i 's/\r$//' "$w/model.pv"   # tolerate a CRLF checkout
  ( cd "$w" && "$PV" model.pv > log.txt 2>&1 ) || true
  sed -n '/Verification summary/,$p' "$w/log.txt" | grep '^Query' | sed 's/^Query //' > "$w/summary.txt"
  if diff -q "models/$d/expected.txt" "$w/summary.txt" >/dev/null; then
    echo "   OK: $(wc -l < "$w/summary.txt") queries match expected.txt"
  else
    echo "   MISMATCH:"; diff "models/$d/expected.txt" "$w/summary.txt" || true; fail=1
  fi
done
exit $fail
