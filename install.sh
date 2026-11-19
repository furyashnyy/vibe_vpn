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
ask_secret() {
  local __name="$1" prompt="$2" answer=''
  read -r -s -p "$prompt: " answer < /dev/tty || die 'interactive tty unavailable'
  printf '\n' > /dev/tty
  printf -v "$__name" '%s' "$answer"
}
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
# Preserve the old binary for a transactional service rollback during upgrades.
PREV_BIN="$TMP/previous-rustine"
if [[ "$MODE" == '--upgrade' && -x /usr/local/bin/rustine ]]; then
  cp /usr/local/bin/rustine "$PREV_BIN"
fi
install_binary
if ! /usr/local/bin/rustine --version >/dev/null 2>&1; then
  if [[ -s "$PREV_BIN" ]]; then
    install -o root -g root -m 0755 "$PREV_BIN" /usr/local/bin/rustine
  fi
  die 'installed binary cannot execute; previous binary restored if available'
fi
mkdir -p /usr/local/lib/rustine
install -o root -g root -m 0755 "$SRC/install.sh" /usr/local/lib/rustine/install.sh
if [[ "$MODE" == '--upgrade' ]]; then
  if systemctl is-active --quiet rustine.service; then
    if ! systemctl restart rustine.service || ! systemctl is-active --quiet rustine.service; then
      log 'Upgrade failed; restoring previous binary.'
      if [[ -s "$PREV_BIN" ]]; then
        install -o root -g root -m 0755 "$PREV_BIN" /usr/local/bin/rustine
        systemctl restart rustine.service || true
      fi
      die 'failed to upgrade running service'
    fi
  fi
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
if [[ "$ROLE" == 'relay' ]]; then
  ask PORT 'Порт текущего сервера (HTTPS сайт и туннель)' 443
else
  ask PORT 'Порт текущего сервера' 8443
fi
[[ "$PORT" =~ ^[0-9]+$ ]] && ((PORT>=1 && PORT<=65535)) || die 'invalid TCP port'
ask SNI 'SNI (DNS-имя ВАШЕГО TLS-сервера)' "${ROLE}.example.net"
[[ "$SNI" =~ ^[a-zA-Z0-9.-]+$ ]] || die 'invalid SNI hostname'
COVER=n
TLS_MODE=selfsigned
if [[ "$ROLE" == 'relay' ]]; then
  ask COVER 'Разместить полноценный HTTPS-сайт на том же порту? [y/n]' y
  [[ "$COVER" =~ ^(y|Y|yes|YES|n|N|no|NO)$ ]] || die 'use y or n'
  if [[ "$COVER" =~ ^(y|Y|yes|YES)$ ]]; then
    ask TLS_MODE 'Сертификат сайта [acme/selfsigned] (acme = публично доверенный)' acme
    [[ "$TLS_MODE" == 'acme' || "$TLS_MODE" == 'selfsigned' ]] || die 'choose acme or selfsigned'
    log "Cover site requires $SNI to be YOUR domain, DNS A/AAAA -> RU_RELAY IP (DNS-only, not proxied)."
  fi
fi
ask_secret PASSWORD 'Секрет для входящих соединений (Enter = сгенерировать)'
if [[ -z "$PASSWORD" ]]; then PASSWORD="$(openssl rand -base64 36 | tr -d '\n')"; fi
[[ "${#PASSWORD}" -ge 16 ]] || die 'password must contain at least 16 characters'
UPSTREAM_PASSWORD=''
if [[ "$ROLE" == 'relay' ]]; then
  ask_secret UPSTREAM_PASSWORD 'Секрет от exit-сервера (обязательно другой, не клиентский)'
  [[ "${#UPSTREAM_PASSWORD}" -ge 16 ]] || die 'exit secret must contain at least 16 characters'
  [[ "$UPSTREAM_PASSWORD" != "$PASSWORD" ]] || die 'incoming and upstream secrets must differ'
fi
ask SPOOF 'Включить SNI-спуфинг? [y/n]' n
case "$SPOOF" in n|N|no|NO) ;; y|Y|yes|YES) die 'forged TCP ClientHello is not implemented: refusing to advertise nonworking feature' ;; *) die 'use y or n' ;; esac
ask AUTO 'Включить автообновление? [y/n]' n
[[ "$AUTO" =~ ^(y|Y|yes|YES|n|N|no|NO)$ ]] || die 'use y or n'
mkdir -p "$PREFIX/tls/server"
chmod 0750 "$PREFIX" "$PREFIX/tls" "$PREFIX/tls/server"
if [[ "$TLS_MODE" == 'acme' ]]; then
  # Certbot owns renewal via HTTP-01 on TCP/80, while Rustine serves HTTPS on TCP/443.
  # A publicly trusted certificate avoids browser security interstitials.
  apt-get install -y -qq --no-install-recommends certbot >/dev/null
  if command -v ufw >/dev/null 2>&1; then ufw allow 80/tcp >/dev/null || true; fi
  log 'Requesting publicly trusted certificate (requires public DNS and reachable TCP/80).'
  certbot certonly --standalone --preferred-challenges http \
    --non-interactive --agree-tos --register-unsafely-without-email -d "$SNI" \
    || die 'ACME HTTP-01 failed; check DNS, Cloudflare DNS-only setting, and TCP/80.'
  CERTDIR="/etc/letsencrypt/live/$SNI"
  [[ -s "$CERTDIR/fullchain.pem" && -s "$CERTDIR/privkey.pem" ]] || die 'certbot did not produce TLS keypair'
  if [[ -e "$PREFIX/tls/server/key.pem" || -e "$PREFIX/tls/server/cert.pem" ]]; then
    mkdir -p "$PREFIX/backups"
    cp -a "$PREFIX/tls/server" "$PREFIX/backups/old-tls-$(date +%Y%m%d-%H%M%S)"
    chmod 0700 "$PREFIX/backups"
  fi
  install -o root -g rustine -m 0644 "$CERTDIR/fullchain.pem" "$PREFIX/tls/server/cert.pem"
  install -o root -g rustine -m 0640 "$CERTDIR/privkey.pem" "$PREFIX/tls/server/key.pem"
  install -o root -g rustine -m 0644 /etc/ssl/certs/ca-certificates.crt "$PREFIX/tls/server/ca.pem"
  openssl x509 -in "$PREFIX/tls/server/cert.pem" -noout -checkhost "$SNI" >/dev/null || die 'wrong ACME certificate SAN'
  # Renewal hook copies root-only certbot material into rustine-readable paths.
  mkdir -p /etc/letsencrypt/renewal-hooks/deploy
  cat > "/etc/letsencrypt/renewal-hooks/deploy/rustine-$SNI.sh" <<HOOK
#!/bin/sh
set -eu
[ "\${RENEWED_LINEAGE:-}" = "$CERTDIR" ] || exit 0
install -o root -g rustine -m 0644 "$CERTDIR/fullchain.pem" "$PREFIX/tls/server/cert.pem"
install -o root -g rustine -m 0640 "$CERTDIR/privkey.pem" "$PREFIX/tls/server/key.pem"
systemctl try-restart rustine.service || true
HOOK
  chmod 0750 "/etc/letsencrypt/renewal-hooks/deploy/rustine-$SNI.sh"
elif [[ -s "$PREFIX/tls/server/cert.pem" && -s "$PREFIX/tls/server/key.pem" && -s "$PREFIX/tls/server/ca.pem" ]]; then
  # Never reuse an existing certificate for a different hostname.
  openssl x509 -in "$PREFIX/tls/server/cert.pem" -noout -checkhost "$SNI" >/dev/null \
    || die "existing TLS certificate does not cover SNI=$SNI; rotate certificates deliberately"
  openssl verify -CAfile "$PREFIX/tls/server/ca.pem" "$PREFIX/tls/server/cert.pem" >/dev/null \
    || die 'existing TLS certificate is expired or not signed by the local CA'
  log 'Existing TLS identity preserved; SAN and trust verified.'
else
  # Incomplete identity? Fail rather than overwriting an existing private CA.
  [[ ! -e "$PREFIX/tls/server/key.pem" && ! -e "$PREFIX/tls/server/cert.pem" && ! -e "$PREFIX/tls/server/ca.pem" ]] \
    || die 'partial TLS identity found; fix or back up the directory before reinstalling'
  "$SRC/scripts/make-certs.sh" "$SNI" "$PREFIX/tls/server"
fi
if [[ "$ROLE" == 'relay' ]]; then
  install -o root -g rustine -m 0640 "$EXIT_CA" "$PREFIX/tls/exit-ca.pem"
fi
printf '%s\n' "$PASSWORD" > "$PREFIX/password"
if [[ "$ROLE" == 'relay' ]]; then
  printf '%s\n' "$UPSTREAM_PASSWORD" > "$PREFIX/upstream-password"
else
  rm -f "$PREFIX/upstream-password"
fi
chown root:rustine "$PREFIX" "$PREFIX/tls" "$PREFIX/tls/server" \
  "$PREFIX/password" "$PREFIX/tls/server/key.pem" "$PREFIX/tls/server/cert.pem" "$PREFIX/tls/server/ca.pem"
chmod 0750 "$PREFIX" "$PREFIX/tls" "$PREFIX/tls/server"
chmod 0640 "$PREFIX/password" "$PREFIX/tls/server/key.pem"
UPSTREAM_UNIT_ENV=''
if [[ "$ROLE" == 'relay' ]]; then
  chown root:rustine "$PREFIX/upstream-password"
  chmod 0640 "$PREFIX/upstream-password"
  UPSTREAM_UNIT_ENV='Environment=RUSTINE_UPSTREAM_PASSWORD_FILE=/etc/rustine/upstream-password'
fi
chmod 0644 "$PREFIX/tls/server/cert.pem" "$PREFIX/tls/server/ca.pem"
cat > "$PREFIX/config.toml" <<CONFIG
role = "$ROLE"
listen = "0.0.0.0:$PORT"
cert_path = "$PREFIX/tls/server/cert.pem"
key_path = "$PREFIX/tls/server/key.pem"
max_padding = 256
max_connections = 256
idle_timeout_secs = 600
jitter_ms = 0
sni_spoofing = false
CONFIG
if [[ "$COVER" =~ ^(y|Y|yes|YES)$ ]]; then
  mkdir -p "$PREFIX/cover"
  # No symlinks in the bundled site; static files owned by root, read by service.
  cp -a "$SRC/cover/site/." "$PREFIX/cover/"
  chown -R root:rustine "$PREFIX/cover"
  find "$PREFIX/cover" -type d -exec chmod 0750 {} +
  find "$PREFIX/cover" -type f -exec chmod 0640 {} +
  cat >> "$PREFIX/config.toml" <<CONFIG
cover_enabled = true
cover_domain = "$SNI"
cover_root = "$PREFIX/cover"
CONFIG
fi
if [[ "$ROLE" == 'relay' ]]; then
  cat >> "$PREFIX/config.toml" <<CONFIG
next_hop = "$EXIT_HOST:$EXIT_PORT"
sni = "$EXIT_SNI"
ca_path = "$PREFIX/tls/exit-ca.pem"
CONFIG
fi
chown root:rustine "$PREFIX/config.toml"
chmod 0640 "$PREFIX/config.toml"
cat > /etc/systemd/system/rustine.service <<UNIT
[Unit]
Description=Rustine | Vibe VPN tunnel
Wants=network-online.target
After=network-online.target
[Service]
Type=simple
User=rustine
Group=rustine
Environment=RUSTINE_PASSWORD_FILE=/etc/rustine/password
${UPSTREAM_UNIT_ENV}
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
if [[ "$ROLE" == 'relay' ]]; then
  VALIDATE_ENV=("RUSTINE_PASSWORD_FILE=$PREFIX/password" "RUSTINE_UPSTREAM_PASSWORD_FILE=$PREFIX/upstream-password")
else
  VALIDATE_ENV=("RUSTINE_PASSWORD_FILE=$PREFIX/password")
fi
if ! env "${VALIDATE_ENV[@]}" /usr/local/bin/rustine --config "$PREFIX/config.toml" check; then
  die 'configuration and TLS material validation failed; service was NOT restarted'
fi
systemctl daemon-reload
systemctl enable rustine.service >/dev/null
systemctl restart rustine.service
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
if [[ "$COVER" =~ ^(y|Y|yes|YES)$ ]]; then
  log "HTTPS website: https://$SNI:$PORT/ (if on 443, standard https://$SNI/)"
  if [[ "$TLS_MODE" == 'selfsigned' ]]; then
    log 'NOTE: self-signed TLS will display a browser trust warning; use ACME for production.'
  fi
fi
log "Share ONLY the CA file $PREFIX/tls/server/ca.pem with the connecting peer."
if [[ "$ROLE" == 'relay' ]]; then
  log "Client: rustine --config configs/client.example.toml (relay_addr=<RU_RELAY_IP>:$PORT; sni=$SNI)"
else
  log 'Supply this server secret and the CA certificate securely to the relay administrator.'
fi
log "Local IP: ${HOST:-unknown}. Password stored root:rustine, not printed in terminal output."
log 'Status: systemctl status rustine; logs: journalctl -u rustine -f'
