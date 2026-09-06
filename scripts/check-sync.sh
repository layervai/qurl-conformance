#!/usr/bin/env bash
# Fail if the npm/python embedded copies drift from canonical /vectors.
set -euo pipefail
cd "$(dirname "$0")/.."
fail=0
for path in vectors/*.json; do
  [ -e "$path" ] || continue
  file=${path##*/}
  for mirror in "npm/vectors/$file" "python/qurl_conformance/_data/$file"; do
    if [ ! -f "$mirror" ]; then
      echo "MISSING mirror $mirror"; fail=1
    elif ! cmp -s "$path" "$mirror"; then
      echo "DRIFT: $mirror differs from $path"; fail=1
    fi
  done
done
for path in npm/vectors/*.json python/qurl_conformance/_data/*.json; do
  [ -e "$path" ] || continue
  if [ ! -f "vectors/${path##*/}" ]; then
    echo "ORPHAN mirror $path"; fail=1
  fi
done
if [ "$fail" = 0 ]; then
  echo "vectors byte-identical across root/npm/python"
else
  echo "sync changed vectors, remove reported orphans, and commit"
  exit 1
fi
