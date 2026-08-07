#!/usr/bin/env bash
set -euo pipefail

profile="$1"; shift
fail=0

for spec in "$@"; do
  pkg="${spec%%:*}"
  want="${spec##*:}"
  got=$(go tool cover -func="$profile" \
        | grep "/$pkg/" \
        | awk '{gsub("%","",$3); s+=$3; n++} END {if (n==0) print 0; else printf "%.1f", s/n}')
  echo "$pkg: $got% (required $want%)"
  awk -v g="$got" -v w="$want" 'BEGIN{exit !(g+0 < w+0)}' && { echo "FAIL: $pkg below threshold"; fail=1; }
done

exit "$fail"
