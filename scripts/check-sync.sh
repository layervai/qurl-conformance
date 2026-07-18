#!/usr/bin/env bash
# Fail if the npm/python embedded copies drift from canonical /vectors.
set -euo pipefail
cd "$(dirname "$0")/.."
fail=0
for f in qv2_conformance_vectors.json issuer_signature_vectors.json relay_knock_golden.json agent_registration_golden.json agent_assignment_golden.json agent_knock_application_vectors.json agent_session_control_vectors.json agent_api_key_id_vectors.json assignment_ticket_v1_vectors.json connector_authority_lambda_v1_vectors.json; do
  a=$(shasum -a 256 "vectors/$f" | awk '{print $1}')
  b=$(shasum -a 256 "npm/vectors/$f" | awk '{print $1}')
  c=$(shasum -a 256 "python/qurl_conformance/_data/$f" | awk '{print $1}')
  if [ "$a" != "$b" ] || [ "$a" != "$c" ]; then
    echo "DRIFT in $f: root=$a npm=$b python=$c"; fail=1
  fi
done
if [ "$fail" = 0 ]; then
  echo "vectors byte-identical across root/npm/python"
else
  echo "run scripts/sync-vectors.sh and commit"
  exit 1
fi
