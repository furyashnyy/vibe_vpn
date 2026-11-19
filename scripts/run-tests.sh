#!/usr/bin/env bash
set -Eeuo pipefail
mkdir -p /reports
REPORT=/reports/report.txt
: > "$REPORT"
FAILURES=0
PASSES=0
start_time=$(date +%s)
cleanup() {
  [[ -z "${CLIENT_PID:-}" ]] || kill "$CLIENT_PID" 2>/dev/null || true
  [[ -z "${TCPDUMP_PID:-}" ]] || kill "$TCPDUMP_PID" 2>/dev/null || true
  [[ -z "${BAD_CLIENT_PID:-}" ]] || kill "$BAD_CLIENT_PID" 2>/dev/null || true
}
trap cleanup EXIT
run_test() {
  local name="$1"; shift
  local start end elapsed status=PASS
  start=$(date +%s)
  echo "[ RUN  ] $name"
  if "$@" > "/reports/$name.log" 2>&1; then
    PASSES=$((PASSES+1))
  else
    status=FAIL
    FAILURES=$((FAILURES+1))
    tail -n 30 "/reports/$name.log" >&2 || true
  fi
  end=$(date +%s); elapsed=$((end-start))
  printf '[ %-4s ] %-22s %4ss\n' "$status" "$name" "$elapsed" | tee -a "$REPORT"
  return 0
}
unit() { cargo test --offline -- --nocapture; }
pcap_parser_unit() { python3 scripts/test_pcap.py -v; }
reject_spoofing_config() {
  if RUSTINE_SNI_SPOOFING=true rustine check > /reports/rejected_spoofing.txt 2>&1; then
    echo 'Unsupported forged ClientHello was incorrectly accepted'; return 1
  fi
  grep -q 'unsupported' /reports/rejected_spoofing.txt
}
reject_invalid_cert() {
  if RUSTINE_CA_PATH=/testcerts/missing.pem rustine check > /reports/rejected_ca.txt 2>&1; then
    echo 'Missing CA was incorrectly accepted'; return 1
  fi
  grep -q 'opening certificate' /reports/rejected_ca.txt
}
wrong_password() {
  RUSTINE_PASSWORD=wrong-unauthorized-password-12345 RUSTINE_LISTEN=127.0.0.1:1081 \
    rustine >/reports/wrong_client.log 2>&1 & BAD_CLIENT_PID=$!
  for n in $(seq 1 30); do
    if rustine health --target 127.0.0.1:1081 >/dev/null 2>&1; then break; fi
    sleep 0.2
  done
  rustine health --target 127.0.0.1:1081 >/dev/null
  if curl --noproxy '' --connect-timeout 8 --max-time 12 -fsS \
    --socks5-hostname 127.0.0.1:1081 http://httpbin:8080/; then
    echo 'Unauthorized client reached the destination'; return 1
  fi
  kill "$BAD_CLIENT_PID" 2>/dev/null || true
  wait "$BAD_CLIENT_PID" 2>/dev/null || true
  BAD_CLIENT_PID=''
  return 0
}
start_client() {
  /usr/local/bin/rustine >/reports/client.log 2>&1 & CLIENT_PID=$!
  for n in $(seq 1 30); do
    if rustine health --target 127.0.0.1:1080 >/dev/null 2>&1; then return 0; fi
    sleep 0.2
  done
  cat /reports/client.log; return 1
}
e2e() {
  start_client
  curl --noproxy '' --connect-timeout 8 --max-time 20 -fsS --socks5-hostname 127.0.0.1:1080 \
    http://httpbin:8080/ | grep -q 'RUSTINE_OK'
  curl --noproxy '' --connect-timeout 8 --max-time 20 -fsS --proxytunnel -x http://127.0.0.1:1080 \
    http://httpbin:8080/ | grep -q 'RUSTINE_OK'
}
packet() {
  timeout 20 tcpdump -i eth0 -n -s 0 -U -w /reports/test.pcap 'tcp port 8443' \
    > /reports/tcpdump.log 2>&1 & TCPDUMP_PID=$!
  sleep 1
  curl --noproxy '' --connect-timeout 8 --max-time 15 -fsS --socks5-hostname 127.0.0.1:1080 \
    http://httpbin:8080/ | grep -q 'RUSTINE_OK'
  sleep 1
  kill "$TCPDUMP_PID" 2>/dev/null || true
  wait "$TCPDUMP_PID" 2>/dev/null || true
  TCPDUMP_PID=""
  python3 scripts/inspect_pcap.py /reports/test.pcap --sni relay.test
}
run_test crypto_framing_unit unit
run_test pcap_parser_unit pcap_parser_unit
run_test forged_sni_rejected reject_spoofing_config
run_test invalid_ca_rejected reject_invalid_cert
run_test end_to_end_tunnel e2e
run_test wrong_password_denied wrong_password
if [[ -n "${CLIENT_PID:-}" ]] && kill -0 "$CLIENT_PID" 2>/dev/null; then
  run_test dpi_packet_smoke packet
else
  echo '[ FAIL ] dpi_packet_smoke (client unavailable)' | tee -a "$REPORT"
  FAILURES=$((FAILURES+1))
fi
# Deliberate SKIP: raw TCP sequence injection isn't implemented; the config must reject it.
echo '[ SKIP ] forged_clienthello_seq (not implemented; config rejects it)' | tee -a "$REPORT"
echo "Summary: $PASSES passed / $FAILURES failed / 1 skipped / $(( $(date +%s)-start_time ))s" | tee -a "$REPORT"
if (( FAILURES > 0 )); then exit 1; fi
exit 0
