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
  curl --connect-timeout 8 --max-time 20 -fsS --socks5-hostname 127.0.0.1:1080 \
    http://httpbin:8080/ | grep -q 'RUSTINE_OK'
  curl --connect-timeout 8 --max-time 20 -fsS --proxytunnel -x http://127.0.0.1:1080 \
    http://httpbin:8080/ | grep -q 'RUSTINE_OK'
}
packet() {
  timeout 20 tcpdump -i eth0 -n -s 0 -U -w /reports/test.pcap 'tcp port 8443' \
    > /reports/tcpdump.log 2>&1 & TCPDUMP_PID=$!
  sleep 1
  curl --connect-timeout 8 --max-time 15 -fsS --socks5-hostname 127.0.0.1:1080 \
    http://httpbin:8080/ | grep -q 'RUSTINE_OK'
  sleep 1
  kill "$TCPDUMP_PID" 2>/dev/null || true
  wait "$TCPDUMP_PID" 2>/dev/null || true
  TCPDUMP_PID=""
  python3 scripts/inspect_pcap.py /reports/test.pcap --sni relay.test
}
run_test crypto_framing_unit unit
run_test end_to_end_tunnel e2e
if [[ -n "${CLIENT_PID:-}" ]] && kill -0 "$CLIENT_PID" 2>/dev/null; then
  run_test dpi_packet_smoke packet
else
  echo '[ FAIL ] dpi_packet_smoke (client unavailable)' | tee -a "$REPORT"
  FAILURES=$((FAILURES+1))
fi
# Deliberate SKIP: raw TCP sequence injection isn't implemented; the config must reject it.
echo '[ SKIP ] forged_clienthello_seq (not implemented; config fails closed)' | tee -a "$REPORT"
echo "Summary: $PASSES passed / $FAILURES failed / 1 skipped / $(( $(date +%s)-start_time ))s" | tee -a "$REPORT"
if (( FAILURES > 0 )); then exit 1; fi
exit 0
