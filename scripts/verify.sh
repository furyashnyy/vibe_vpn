#!/usr/bin/env bash
# Local prerequisite checks. Does not require cargo, Docker, network, or root.
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
mkdir -p reports
REPORT=reports/static-report.txt
: > "$REPORT"
passes=0
failures=0
skips=0
started=$(date +%s)
run() {
  local name="$1"; shift
  local start=$SECONDS status=PASS
  printf '[ RUN  ] %s\n' "$name"
  if "$@" > "reports/static-$name.log" 2>&1; then
    passes=$((passes + 1))
  else
    failures=$((failures + 1))
    status=FAIL
    tail -n 25 "reports/static-$name.log" >&2 || true
  fi
  printf '[ %-4s ] %-24s %4ss\n' "$status" "$name" "$((SECONDS - start))" | tee -a "$REPORT"
}
shell_syntax() {
  local script
  for script in install.sh scripts/*.sh; do bash -n "$script"; done
}
config_syntax() {
  python3 - <<'PY'
import pathlib, tomllib
for path in [pathlib.Path('Cargo.toml'), *pathlib.Path('configs').glob('*.toml')]:
    with path.open('rb') as source: tomllib.load(source)
    print('TOML OK:', path)
with pathlib.Path('Cargo.toml').open('rb') as source:
    cargo = tomllib.load(source)
assert 'env' not in cargo['dependencies']['serde'].get('features', []), 'serde has no env feature'
assert cargo['package']['edition'] == '2024'
print('Cargo package:', cargo['package']['name'], cargo['package']['version'])
PY
}
certificates() {
  local tmp
  tmp=$(mktemp -d)
  # A function-local trap is not reliable inside subshells; run inside a subshell.
  (
    trap 'rm -rf "$tmp"' EXIT
    bash scripts/make-certs.sh relay.test "$tmp/relay"
    openssl verify -CAfile "$tmp/relay/ca.pem" "$tmp/relay/cert.pem"
    openssl x509 -in "$tmp/relay/cert.pem" -noout -ext subjectAltName | grep -q 'DNS:relay.test'
    openssl x509 -in "$tmp/relay/cert.pem" -noout -checkend 3600 | grep -q 'will not expire'
  )
}
run shell_syntax shell_syntax
run config_syntax config_syntax
run tls_certificates certificates
run pcap_parser python3 scripts/test_pcap.py -v
run routing_unit python3 scripts/test-routing.py -v
if python3 -c 'import yaml' >/dev/null 2>&1; then
  run yaml_syntax python3 -c 'import yaml; [yaml.safe_load(open(p)) for p in ("docker-compose.yml", "docker-compose.test.yml")]'
else
  skips=$((skips+1))
  echo '[ SKIP ] yaml_syntax (optional Python PyYAML unavailable)' | tee -a "$REPORT"
fi
if [[ "${1:-}" == '--cargo' ]]; then
  if command -v cargo >/dev/null 2>&1; then
    run cargo_tests cargo test --all-targets
  else
    failures=$((failures+1))
    echo '[ FAIL ] cargo_tests (--cargo requested but cargo unavailable)' | tee -a "$REPORT"
  fi
else
  skips=$((skips+1))
  echo '[ SKIP ] cargo_tests (run verify.sh --cargo or use the Docker suite)' | tee -a "$REPORT"
fi
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  run compose_syntax docker compose -f docker-compose.test.yml config --quiet
else
  skips=$((skips+1))
  echo '[ SKIP ] compose_syntax (Docker Compose unavailable)' | tee -a "$REPORT"
fi
printf 'Summary: %s passed / %s failed / %s skipped / %ss\n' \
  "$passes" "$failures" "$skips" "$(( $(date +%s) - started ))" | tee -a "$REPORT"
(( failures == 0 ))
