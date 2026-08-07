#!/usr/bin/env bash
set -euo pipefail

require_all=0
if [ "${1:-}" = "--require-all" ]; then
  require_all=1
  shift
fi

profile="$1"; shift

# Read the profile once, and fail hard if it cannot be read at all. An
# unreadable profile must never be mistaken for "package does not exist
# yet" — that would let the gate pass green on the very packages it is
# meant to guard.
#
# go tool cover -func always prints a total line and exits 0, even for an
# empty or mode-only profile — so an empty $funcs is not a detectable
# state here. A degenerate profile shows up as every package being
# skipped; pass --require-all to turn that into a failure once all
# packages are expected to exist.
if ! funcs=$(go tool cover -func="$profile" 2>&1); then
  echo "FAIL: cannot read coverage profile $profile" >&2
  printf '%s\n' "$funcs" >&2
  exit 1
fi

fail=0
checked=0
total=0

for spec in "$@"; do
  pkg="${spec%%:*}"
  want="${spec##*:}"
  total=$((total + 1))

  # Now this really only means "not in the profile" — the profile itself
  # is known good.
  lines=$(printf '%s\n' "$funcs" | grep "/$pkg/" || true)
  if [ -z "$lines" ]; then
    if [ "$require_all" -eq 1 ]; then
      echo "FAIL: $pkg not present in profile (--require-all)"
      fail=1
    else
      echo "$pkg: not present in profile — skipped"
    fi
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

if [ "$require_all" -eq 1 ]; then
  echo "checked $checked of $total packages (mode: --require-all)"
else
  echo "checked $checked of $total packages (mode: normal)"
fi
exit "$fail"
