#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
docker build -t github-ngit-mirror:local .
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/workspace" \
  github-ngit-mirror:local setup --org "${1:-sandwichfarm}" \
  --config /workspace/config.json --secrets /workspace/secrets
