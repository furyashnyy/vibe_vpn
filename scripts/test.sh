#!/usr/bin/env bash
set -Eeuo pipefail
mkdir -p reports
# --exit-code-from tester propagates the test container status to the shell.
docker compose -f docker-compose.test.yml up --build --exit-code-from tester
