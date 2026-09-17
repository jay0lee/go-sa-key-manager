#!/usr/bin/env bash
#
# cleanup_gcp_live_test.sh
#
# Cleans up the GCP test projects and folder created for live testing.

set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <project-id-1> [project-id-2 ...] [folder-id]"
  exit 1
fi

echo "Cleaning up live test resources..."

for ARG in "$@"; do
  if [[ "${ARG}" =~ ^[0-9]+$ ]]; then
    echo "Deleting folder ${ARG}..."
    gcloud resource-manager folders delete "${ARG}" --quiet || true
  else
    echo "Deleting project ${ARG}..."
    gcloud projects delete "${ARG}" --quiet || true
  fi
done

echo "Cleanup complete."
