#!/usr/bin/env bash
set -euo pipefail

profile="$1"; shift
fail=0
checked=0
total=0

for spec in "$@"; do
  pkg="${spec%%:*}"
  want="${spec##*:}"
  total=$((total + 1))

  # A package that does not exist yet is not a failure — it is reported and
  # skipped. The summary below makes an unexpected skip visible.
  lines=$(go tool cover -func="$profile" | grep "/$pkg/" || true)
  if [ -z "$lines" ]; then
    echo "$pkg: no coverage data — skipped"
    continue
  fi

  got=$(printf '%s\n' "$lines" \
        | awk '{gsub("%","",$3); s+=$3; n++} END {printf "%.1f", s/n}')
  echo "$pkg: $got% (required $want%)"
  checked=$((checked + 1))

  if awk -v g="$got" -v w="$want" 'BEGIN{exit !(g+0 < w+0)}'; then
    echo "FAIL: $pkg below threshold"
    fail=1
  fi
done

echo "checked $checked of $total packages"
exit "$fail"
