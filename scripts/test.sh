#!/usr/bin/env bash
set -Eeuo pipefail
mkdir -p reports
# Docker image includes all test tooling; host Python/cargo are not required.
# --exit-code-from tester propagates the test container status to the shell.
docker compose -f docker-compose.test.yml up --build --exit-code-from tester
