#!/usr/bin/env bash
# Scanner end-to-end test: installs WordPress with popular plugins in Docker, then
#   1. scans the clean site, every warning or error there is a false positive
#   2. plants the inert samples from samples/ and checks that each one is reported
# Needs only Docker. Usage: tests/e2e/run.sh
set -euo pipefail

cd "$(dirname "$0")"
trap 'docker compose down -v --remove-orphans >/dev/null 2>&1' EXIT

docker compose pull --quiet
docker compose run --rm cli
