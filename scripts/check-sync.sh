#!/usr/bin/env bash
# Fail if the npm/python embedded copies drift from canonical /vectors.
set -euo pipefail
cd "$(dirname "$0")/.."
fail=0
for path in vectors/*.json; do
  file=${path##*/}
  if ! cmp -s "$path" "npm/vectors/$file" || ! cmp -s "$path" "python/qurl_conformance/_data/$file"; then
    echo "DRIFT in $file"; fail=1
  fi
done
for path in npm/vectors/*.json python/qurl_conformance/_data/*.json; do
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
