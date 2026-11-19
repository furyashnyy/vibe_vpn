#!/usr/bin/env bash
# Rustine installer for Debian 12 / Ubuntu 22.04+ (systemd).
# Interactive input comes from /dev/tty, so `curl ... | sudo bash` works.
set -Eeuo pipefail
umask 027
PROJECT='furyashnyy/vibe_vpn'
PREFIX=/etc/rustine
MODE="${1:-install}"
log() { printf '[rustine] %s\n' "$*"; }
die() { log "ERROR: $*" >&2; exit 1; }
ask() { local __name="$1" prompt="$2" default="${3:-}" answer='';
  if [[ -n "$default" ]]; then
    read -r -p "$prompt [$default]: " answer < /dev/tty || die 'interactive tty unavailable'
  else
    read -r -p "$prompt: " answer < /dev/tty || die 'interactive tty unavailable'
  fi
  printf -v "$__name" '%s' "${answer:-$default}"
}
require_root() { [[ "$EUID" -eq 0 ]] || die 'run with sudo / as root'; }
require_root
if [[ "$MODE" == '--uninstall' ]]; then
  systemctl disable --now rustine-update.timer rustine.service 2>/dev/null || true
  rm -f /etc/systemd/system/{rustine.service,rustine-update.service,rustine-update.timer}
  systemctl daemon-reload
  rm -f /usr/local/bin/rustine
  rm -rf /usr/local/lib/rustine "$PREFIX"
  log 'Uninstalled service, binary, and private keys; any UFW rule must be reviewed manually.'
  exit 0
fi
[[ "$MODE" == 'install' || "$MODE" == '--upgrade' ]] || die 'usage: install.sh [--upgrade|--uninstall]'
command -v apt-get >/dev/null || die 'only Debian/Ubuntu apt-based distributions are supported'
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends curl jq ufw ca-certificates \
  tar gzip openssl git build-essential pkg-config >/dev/null
if ! command -v docker >/dev/null 2>&1; then
  apt-get install -y -qq --no-install-recommends docker.io >/dev/null || log 'Docker could not be installed; systemd mode remains available.'
fi
if ! docker compose version >/dev/null 2>&1; then
  apt-get install -y -qq --no-install-recommends docker-compose-v2 >/dev/null 2>&1 || \
  apt-get install -y -qq --no-install-recommends docker-compose-plugin >/dev/null 2>&1 || \
  log 'Docker Compose plugin unavailable from this distribution; install it separately if required.'
fi
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
SRC=''
source_checkout() {
  if [[ -f "${PWD}/Cargo.toml" && -f "${PWD}/src/main.rs" && -f "${PWD}/install.sh" ]]; then
    SRC="$PWD"
  else
    log "Retrieving source from https://github.com/$PROJECT"
    curl -fL --retry 2 -o "$TMP/source.tar.gz" "https://github.com/$PROJECT/archive/refs/heads/main.tar.gz" \
      || die 'cannot download source; use a cloned repository'
    mkdir -p "$TMP/src"
    tar -xzf "$TMP/source.tar.gz" -C "$TMP/src" --strip-components=1
    SRC="$TMP/src"
  fi
  [[ -f "$SRC/Cargo.toml" ]] || die 'source tree incomplete'
}
install_binary() {
  local arch release
  arch="$(uname -m)"
  release="https://github.com/$PROJECT/releases/latest/download/rustine-linux-${arch}.tar.gz"
  if curl -fL --retry 1 --connect-timeout 8 --max-time 40 -o "$TMP/release.tar.gz" "$release" >/dev/null 2>&1; then
    mkdir -p "$TMP/release"
    tar -xzf "$TMP/release.tar.gz" -C "$TMP/release" || die 'release archive invalid'
    [[ -f "$TMP/release/rustine" ]] || die 'release archive missing rustine binary'
    install -o root -g root -m 0755 "$TMP/release/rustine" /usr/local/bin/rustine
    log 'Installed latest release binary (verify release provenance before trusting it).'
    return
  fi
  log 'No compatible GitHub Release found; compiling locally.'
  local cargo_bin=''
  if command -v cargo >/dev/null 2>&1 && rustc --version 2>/dev/null | awk '{split($2,v,".");exit !(v[1]>1 || (v[1]==1 && v[2]>=85))}'; then
    cargo_bin="$(command -v cargo)"
  else
    log 'Installing Rust stable toolchain (MSRV >= 1.85).'
    export RUSTUP_HOME=/opt/rustine/rustup CARGO_HOME=/opt/rustine/cargo
    mkdir -p "$RUSTUP_HOME" "$CARGO_HOME"
    curl -fLsS https://sh.rustup.rs -o "$TMP/rustup-init.sh"
    sh "$TMP/rustup-init.sh" -y --profile minimal --default-toolchain stable --no-modify-path
    cargo_bin="$CARGO_HOME/bin/cargo"
  fi
  source_checkout
  "$cargo_bin" build --release --manifest-path "$SRC/Cargo.toml"
  install -o root -g root -m 0755 "$SRC/target/release/rustine" /usr/local/bin/rustine
}
source_checkout
install_binary
mkdir -p /usr/local/lib/rustine
install -o root -g root -m 0755 "$SRC/install.sh" /usr/local/lib/rustine/install.sh
if [[ "$MODE" == '--upgrade' ]]; then
  systemctl try-restart rustine.service || true
  log 'Upgrade complete; configuration unchanged.'
  exit 0
fi
if ! id rustine >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin rustine
fi
ask ROLE 'Роль сервера [relay/exit]' relay
[[ "$ROLE" == 'relay' || "$ROLE" == 'exit' ]] || die 'choose relay or exit'
EXIT_HOST=''; EXIT_PORT='8443'; EXIT_SNI=''; EXIT_CA=''
if [[ "$ROLE" == 'relay' ]]; then
  ask EXIT_HOST 'IP или домен exit-сервера' ''
  [[ -n "$EXIT_HOST" ]] || die 'exit address required'
  ask EXIT_PORT 'Порт exit-сервера' 8443
  ask EXIT_SNI 'SNI exit-сервера (должен совпасть с его сертификатом)' exit.example.net
  ask EXIT_CA 'Путь к файлу ca.pem, скопированному с exit-сервера' ''
  [[ -s "$EXIT_CA" ]] || die 'copy exit/ca.pem from exit VPS first (not ca.key!)'
fi
ask PORT 'Порт текущего сервера' 8443
[[ "$PORT" =~ ^[0-9]+$ ]] && ((PORT>=1 && PORT<=65535)) || die 'invalid TCP port'
ask SNI 'SNI (DNS-имя ВАШЕГО TLS-сервера)' "${ROLE}.example.net"
[[ "$SNI" =~ ^[a-zA-Z0-9.-]+$ ]] || die 'invalid SNI hostname'
ask PASSWORD 'Пароль/UUID (Enter = сгенерировать случайный секрет)' ''
if [[ -z "$PASSWORD" ]]; then PASSWORD="$(openssl rand -base64 36 | tr -d '\n')"; fi
[[ "${#PASSWORD}" -ge 16 ]] || die 'password must contain at least 16 characters'
ask SPOOF 'Включить SNI-спуфинг? [y/n]' n
case "$SPOOF" in n|N|no|NO) ;; y|Y|yes|YES) die 'forged TCP ClientHello is not implemented: refusing to advertise nonworking feature' ;; *) die 'use y or n' ;; esac
ask AUTO 'Включить автообновление? [y/n]' n
[[ "$AUTO" =~ ^(y|Y|yes|YES|n|N|no|NO)$ ]] || die 'use y or n'
mkdir -p "$PREFIX/tls/server"
chmod 0750 "$PREFIX" "$PREFIX/tls" "$PREFIX/tls/server"
if [[ ! -s "$PREFIX/tls/server/cert.pem" || ! -s "$PREFIX/tls/server/key.pem" ]]; then
  "$SRC/scripts/make-certs.sh" "$SNI" "$PREFIX/tls/server"
else
  log 'Existing TLS certificate preserved. Ensure its SAN matches the selected SNI.'
fi
if [[ "$ROLE" == 'relay' ]]; then
  install -o root -g rustine -m 0640 "$EXIT_CA" "$PREFIX/tls/exit-ca.pem"
fi
printf '%s\n' "$PASSWORD" > "$PREFIX/password"
chown root:rustine "$PREFIX" "$PREFIX/tls" "$PREFIX/tls/server" \
  "$PREFIX/password" "$PREFIX/tls/server/key.pem" "$PREFIX/tls/server/cert.pem" "$PREFIX/tls/server/ca.pem"
chmod 0750 "$PREFIX" "$PREFIX/tls" "$PREFIX/tls/server"
chmod 0640 "$PREFIX/password" "$PREFIX/tls/server/key.pem"
chmod 0644 "$PREFIX/tls/server/cert.pem" "$PREFIX/tls/server/ca.pem"
cat > "$PREFIX/config.toml" <<CONFIG
role = "$ROLE"
listen = "0.0.0.0:$PORT"
cert_path = "$PREFIX/tls/server/cert.pem"
key_path = "$PREFIX/tls/server/key.pem"
max_padding = 256
jitter_ms = 0
sni_spoofing = false
CONFIG
if [[ "$ROLE" == 'relay' ]]; then
  cat >> "$PREFIX/config.toml" <<CONFIG
next_hop = "$EXIT_HOST:$EXIT_PORT"
sni = "$EXIT_SNI"
ca_path = "$PREFIX/tls/exit-ca.pem"
CONFIG
fi
chown root:rustine "$PREFIX/config.toml"
chmod 0640 "$PREFIX/config.toml"
cat > /etc/systemd/system/rustine.service <<'UNIT'
[Unit]
Description=Rustine | Vibe VPN tunnel
Wants=network-online.target
After=network-online.target
[Service]
Type=simple
User=rustine
Group=rustine
Environment=RUSTINE_PASSWORD_FILE=/etc/rustine/password
ExecStart=/usr/local/bin/rustine --config /etc/rustine/config.toml
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
[Install]
WantedBy=multi-user.target
UNIT
cat > /etc/systemd/system/rustine-update.service <<'UNIT'
[Unit]
Description=Update Rustine from GitHub release or trusted source
[Service]
Type=oneshot
ExecStart=/usr/local/lib/rustine/install.sh --upgrade
UNIT
cat > /etc/systemd/system/rustine-update.timer <<'UNIT'
[Unit]
Description=Daily Rustine update check
[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true
[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now rustine.service
if [[ "$AUTO" =~ ^(y|Y|yes|YES)$ ]]; then
  systemctl enable --now rustine-update.timer
else
  systemctl disable --now rustine-update.timer 2>/dev/null || true
fi
# Do NOT enable UFW automatically: doing so can lock SSH administrators out.
if command -v ufw >/dev/null 2>&1; then ufw allow "${PORT}/tcp" >/dev/null || log 'Review UFW manually'; fi
if ! systemctl is-active --quiet rustine.service; then
  journalctl -u rustine.service -n 40 --no-pager || true
  die 'service failed to start'
fi
HOST=$(hostname -I 2>/dev/null | awk '{print $1}')
log "Role: $ROLE | TCP port: $PORT | local certificate SNI: $SNI"
log "Share ONLY the CA file $PREFIX/tls/server/ca.pem with the connecting peer."
log "Connection template: rustine://<RU_RELAY_IP>:$PORT?sni=$SNI (client must trust the CA PEM and have the shared secret)."
log "Local IP: ${HOST:-unknown}. Password stored root:rustine, not printed in terminal output."
log 'Status: systemctl status rustine; logs: journalctl -u rustine -f'
