#!/usr/bin/env bash
# Propagate the canonical /vectors JSON into the npm and python package dirs.
# Run after editing anything under /vectors, and commit all copies together.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p npm/vectors python/qurl_conformance/_data
for f in qv2_conformance_vectors.json issuer_signature_vectors.json relay_knock_golden.json agent_registration_golden.json agent_knock_application_vectors.json; do
  cp "vectors/$f" "npm/vectors/$f"
  cp "vectors/$f" "python/qurl_conformance/_data/$f"
done
echo "synced vectors -> npm/vectors, python/qurl_conformance/_data"
