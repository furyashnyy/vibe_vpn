# Rustine / Vibe VPN

**Two-hop authenticated TLS tunnel** · Rust 2024 · Linux / Docker

```
SOCKS5 or HTTP CONNECT       TLS 1.3 + ChaCha20-Poly1305         TLS 1.3 + AEAD
       client  ────────────────────────►  RU_RELAY  ───────────────────►  FOREIGN_EXIT ──► Internet
       :1080                          :8443                          :8443
```

Rustine provides end-to-end routing through a relay (the relay terminates and re-encrypts each hop). Traffic uses **real TLS 1.3**, authenticated with private CA certificates and an additional shared-secret HMAC challenge. Randomized padding sits inside encrypted frames. The exit resolves destinations, and rejects private/reserved IPs by default.

## Run

1. On **FOREIGN_EXIT**, run `sudo bash install.sh`, choose `exit`, set a DNS name for its certificate. Copy `/etc/rustine/tls/server/ca.pem` securely to RU_RELAY.
2. On **RU_RELAY**, run the same installer, choose `relay`, enter the exit address, its certificate DNS name and the copied CA PEM. **Use the same strong password on both servers.** Copy the relay CA PEM securely to the client.
3. On the client, set `RUSTINE_PASSWORD` (or `RUSTINE_PASSWORD_FILE`), adapt `configs/client.example.toml` and run:

```bash
cargo run --release -- --config configs/client.example.toml
curl --socks5-hostname 127.0.0.1:1080 https://example.com
```

Both server roles also run with Compose on separate VPSs. Set `.env` from `.env.example`, generate the TLS identities (`scripts/make-certs.sh exit.example.net tls/exit` and `scripts/make-certs.sh relay.example.net tls/relay`), copy `tls/exit/ca.pem` to `tls/exit-ca.pem` on relay, write `secrets/password` on each host, and grant container UID/GID `10001` read access to the private keys and secret:

```bash
sudo chgrp -R 10001 tls secrets && sudo chmod 750 tls tls/exit tls/relay secrets
sudo chmod 640 tls/*/key.pem secrets/password
# Foreign VPS:
docker compose --profile foreign up -d --build
# RU VPS:
docker compose --profile ru up -d --build
```

Installer supports `curl -fsSL https://raw.githubusercontent.com/furyashnyy/vibe_vpn/main/install.sh | sudo bash` (**review the script first**), `sudo bash install.sh --upgrade`, and `sudo bash install.sh --uninstall`. It uses systemd and does not enable UFW globally. Install via repository checkout for a version-controlled deployment.

## Tests (VPS, no GitHub Actions)

```bash
git pull
bash scripts/test.sh
# Or the basic command (does not reliably propagate the tester's exit code):
docker compose -f docker-compose.test.yml up --build --abort-on-container-exit
```

Tests cover AEAD/key derivation/framing, `client → relay → exit → httpbin`, HTTP CONNECT, and a PCAP TLS/SNI smoke check. Results: `reports/report.txt`, individual logs, `reports/test.pcap`. `scripts/test.sh` uses `--exit-code-from tester` to guarantee a nonzero result on test failure.

## Status / limitations

| Capability | Status |
|---|---|
| TCP, SOCKS5, HTTP CONNECT, TLS 1.3, AEAD, 2-hop relay | Implemented; compilation/integration must be verified on a Rust/Docker host |
| Configurable SNI | **Only with a certificate trusted by the client** |
| Random encrypted frame padding, optional jitter | Implemented; not a DPI bypass guarantee |
| Fake ClientHello / invalid TCP sequence | **TODO** — explicitly rejected, never silently enabled |
| QUIC, TLS-in-TLS fingerprint defenses, active probing responses | **TODO** |
| Direct bypass of IP-based whitelists / arbitrary third-party SNI | **Not guaranteed**; needs real permitted routing and network testing |

**Security:** No public proxy listener on the client by default. Do not commit passwords or CA private keys; rotate certificates and secrets on compromise. Avoid claims of resistance to sophisticated traffic analysis without independent measurements. This is an MVP, not a security-audited VPN.