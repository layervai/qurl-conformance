#!/usr/bin/env bash
# Propagate the canonical /vectors JSON into the npm and python package dirs.
# Run after editing anything under /vectors, and commit all copies together.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p npm/vectors python/qurl_conformance/_data
for path in vectors/*.json; do
  file=${path##*/}
  cp "$path" "npm/vectors/$file"
  cp "$path" "python/qurl_conformance/_data/$file"
done
echo "synced vectors -> npm/vectors, python/qurl_conformance/_data"
