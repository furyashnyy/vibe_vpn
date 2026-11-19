# Rustine / Vibe VPN

**Rust 2024 · two-hop TLS tunnel · self-hosted HTTPS cover · selective routing**

Rustine connects a local SOCKS5/HTTP CONNECT client to an RU relay, which forwards authenticated traffic to a foreign exit. It is an experimental TCP proxy, **not** an implementation of VLESS/XTLS-Reality.

```text
Browser / apps
  ├── Russian domains and IP ranges ──────── direct (client-side rules)
  └── Other TCP ─── SOCKS5 ─── RU_RELAY ─── FOREIGN_EXIT ─── Internet
                                 │
                     HTTPS website on :443
                      for ordinary browsers
```

## Architecture

| Component | Listener | Purpose |
|---|---|---|
| `client` | `127.0.0.1:1080` | SOCKS5 and HTTP CONNECT |
| `relay` | `:443/tcp` | Authenticated tunnel + public static HTTPS website |
| `exit` | `:8443/tcp` | Destination TCP connections |

Every hop uses verified TLS 1.3, distinct PSKs, and AEAD frames. The relay only connects to its configured exit. HTTPS requests on the same port are served from `cover/site/`, including HTML, CSS, assets and `404` responses. **The SNI must be a domain you own, with a matching certificate**; a third-party SNI or a cover site does not unblock an IP-level ban.

## Deploy

Install on the **exit first** (Debian/Ubuntu, root), then copy its public `ca.pem` securely to the relay. Run the same installer on the RU relay:

```bash
sudo bash install.sh
```

Choose `exit` or `relay`. For the relay, select port **443**, enable the website and choose `acme` to issue a publicly trusted TLS certificate. Requirements: DNS **A/AAAA → RU relay IP** (Cloudflare **DNS-only**), TCP ports **80** (ACME renewal) and **443**, domain fully under your control. The installer configures `certbot` renewal and keeps the TLS private key on the server. The site files are copied into `/etc/rustine/cover/` and can be edited there.

For Docker Compose, create `.env` from `.env.example`, generate/provide certs and secrets, then deploy profiles on **different hosts**:

```bash
cp .env.example .env
# On the foreign VPS:
docker compose --profile foreign up -d --build
# On the RU VPS:
docker compose --profile ru up -d --build
```

Enable `COVER_ENABLED=true` on the relay after supplying an operator-owned TLS certificate and matching `RELAY_DOMAIN`. Docker Compose **does not** provision certificates; the interactive installer supports Certbot.

## Routing: Russian sites direct

Start the Rustine client on your PC before configuring routing. Two client modes are provided:

**Browser only** — generate PAC and configure a browser to use it:

```bash
python3 scripts/generate-routing.py --mode pac --output rustine.pac
```

`.ru`, `.su`, `.рф` and local addresses use `DIRECT`; all other browser requests use `SOCKS5 127.0.0.1:1080`. This does **not** cover native apps or IP geolocation. If the SOCKS proxy is unavailable, non-RU requests fail rather than silently falling back to direct access.

**System TCP traffic (Windows/Linux)** — generate a [sing-box](https://sing-box.sagernet.org/) 1.14+ TUN config:

```bash
python3 scripts/generate-routing.py --mode tun --relay-ip <RU_RELAY_PUBLIC_IP> --output rustine-tun.json
sing-box check -c rustine-tun.json
# Administrator/root rights are required for TUN:
sing-box run -c rustine-tun.json
```

TUN excludes the **RU relay IP** to prevent recursive proxying. It routes `.ru/.su/.рф` and RU GeoIP ranges directly, routes other TCP through Rustine SOCKS5, and blocks non-DNS UDP (Rustine has no UDP tunnel yet). The `geoip-ru.srs` rule-set is downloaded via Rustine; initial startup requires a working SOCKS5 proxy. DNS uses a local resolver; DNS privacy and all applications' routing still require verification on the target operating system.

## Verification

```bash
git pull
bash scripts/verify.sh                 # Python/Bash/OpenSSL tests
bash scripts/verify.sh --cargo         # also run Rust unit tests
bash scripts/test.sh                   # Docker TCP / TLS / website / DPI smoke tests
```

Reports: `reports/`. `rustine --config /etc/rustine/config.toml check` validates server configuration and TLS material. See `configs/` for TOML examples. Use `sudo bash install.sh --upgrade` for installed systemd services and `--uninstall` to remove them.

## Boundaries

This is **not a complete VPN**: TUN currently forwards TCP only; no UDP relay, IPv6 route leak audit, QUIC, or XTLS-Reality. Forged ClientHello injection is explicitly unsupported, and neither TLS padding nor a real site guarantees resistance to active probing or regional IP blocking. Validate all deployment paths and Rust compilation before production use.

MIT · Rustine contributors
