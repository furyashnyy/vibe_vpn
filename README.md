# Rustine / Vibe VPN

**v0.3.0** — reliability and deployment hardening.

**Two-hop authenticated TLS proxy** · Rust 2024 · Linux / Docker

```text
SOCKS5 / HTTP CONNECT          TLS 1.3 + AEAD                 TLS 1.3 + AEAD
  Client :1080  ─────────────► RU_RELAY :8443 ─────────────► FOREIGN_EXIT :8443 ──► Internet
                  PSK: relay                   PSK: exit
```

A small, independently configured TCP tunnel. Each hop uses **real TLS 1.3**, validates a privately issued certificate and performs challenge-response authentication before exchanging ChaCha20-Poly1305 frames. Relay and exit **must have different secrets**; clients never receive the exit secret. By default, the exit refuses private/reserved destinations, and the client binds only to loopback. Server connections are capped at 256, and authenticated idle streams time out after 600 seconds (both configurable).

## Install · systemd

On both VPSs, use a reviewed checkout (Debian/Ubuntu):

```bash
 git clone https://github.com/furyashnyy/vibe_vpn.git
 cd vibe_vpn
 sudo bash install.sh
```

1. **FOREIGN_EXIT:** choose `exit`; the installer generates a certificate and an exit secret. Securely copy `/etc/rustine/tls/server/ca.pem` and the generated exit secret to the RU relay administrator.
2. **RU_RELAY:** choose `relay`; provide exit address, exact exit certificate hostname (SNI), copied CA, **its exit secret**, and a **different** incoming client secret. Securely copy its `ca.pem` and incoming secret to your client.
3. **Client:** configure `configs/client.example.toml`; set `RUSTINE_PASSWORD_FILE` or `RUSTINE_PASSWORD` to the **relay** secret, then run:

```bash
cargo run --release -- --config configs/client.example.toml
curl --socks5-hostname 127.0.0.1:1080 https://example.com
```

The installer supports `--upgrade` (keeps config, rolls back the previous binary if service restart fails) and `--uninstall` (removes local keys and service). It deliberately does **not** enable UFW globally. The `--upgrade` timer is opt-in; review release provenance before enabling unattended updates.

## Docker Compose

Use **separate hosts** and `.env` based on `.env.example`. Generate each host's certificate with `scripts/make-certs.sh <your-hostname> tls/<role>`. The exit keeps `secrets/exit-password`. The relay needs both its distinct `secrets/relay-password` and the exit's `secrets/exit-password`, plus a copy of the exit CA at `tls/exit-ca.pem`. Do **not** copy the CA private key. Grant runtime container GID 10001 access to certificates and secrets:

```bash
sudo chgrp -R 10001 tls secrets
sudo chmod 750 tls secrets tls/*/
sudo chmod 640 tls/*/key.pem secrets/*
# Foreign VPS:
docker compose --profile foreign up -d --build
# RU VPS:
docker compose --profile ru up -d --build
```

Only the matching profile is started on each VPS. The default exit egress policy denies loopback/private/reserved IPs. `ALLOW_PRIVATE_TARGETS=true` is intended **only** for isolated testing.

## Tests · no GitHub Actions

```bash
git pull
bash scripts/verify.sh  # Bash/TOML/TLS/PCAP; runs without Docker
bash scripts/test.sh    # build + integration tests; requires Docker
# Direct Compose invocation (unlike test.sh, may not propagate tester exit status):
docker compose -f docker-compose.test.yml up --build --abort-on-container-exit
```

Tests: crypto/framing, split-TCP PCAP parser, two-hop SOCKS5 and HTTP CONNECT, wrong-password denial, invalid certificate rejection, unsupported SNI spoof rejection and structural TLS/SNI PCAP inspection. The Docker report is `reports/report.txt`; the offline check report is `reports/static-report.txt`. Detailed logs and capture are saved beside them. `scripts/test.sh` uses `--exit-code-from tester`, yielding nonzero exit on a failing test.

## Scope

| Capability | Status |
| --- | --- |
| SOCKS5, HTTP CONNECT, TCP relay, TLS 1.3, AEAD | Implemented; end-to-end Docker verification pending |
| Separate hop secrets, trusted CA, client loopback guard | Implemented |
| Configurable SNI | Must match a certificate the caller trusts |
| Encrypted padding, optional jitter | Implemented, **not** an anti-DPI guarantee |
| Forged ClientHello / false TCP sequence, QUIC | **TODO**; forged packet flag is rejected |
| Whitelist/IP blocking bypass | Not guaranteed; both physical links must be reachable |

**Security note:** A relay terminates the first TLS+AEAD hop and can inspect forwarded data. The project has not received an external security audit. Never commit secrets or CA private keys. A TLS packet smoke test cannot demonstrate resistance to active probing or sophisticated traffic analysis.
