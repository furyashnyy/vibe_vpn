#!/usr/bin/env python3
"""Generate PAC or sing-box >=1.14 TUN routing for Rustine SOCKS5 client.
TUN routes TCP via Rustine; non-DNS UDP is blocked (Rustine has no UDP).
"""
import argparse
import ipaddress
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]


def generate_pac(proxy_host: str, proxy_port: int) -> str:
    if not (proxy_host == '127.0.0.1' or proxy_host == 'localhost'):
        raise ValueError('PAC only supports loopback SOCKS5 proxy')
    if not 1 <= proxy_port <= 65535:
        raise ValueError('invalid proxy port')
    template = (ROOT / 'routing/rustine.pac').read_text(encoding='utf8')
    return template.replace('SOCKS5 127.0.0.1:1080', f'SOCKS5 {proxy_host}:{proxy_port}')


def generate_tun(relay_ip: str, proxy_host: str, proxy_port: int) -> dict:
    if proxy_host not in ('127.0.0.1', 'localhost'):
        raise ValueError('TUN SOCKS5 proxy must be loopback')
    if not 1 <= proxy_port <= 65535:
        raise ValueError('invalid port')
    address = ipaddress.ip_address(relay_ip)
    if not address.is_global:
        raise ValueError('relay IP must be a public, globally routed IP (not an RFC1918/loopback address)')
    net = f'{address}/{32 if address.version == 4 else 128}'
    return {
        'log': {'level': 'warn'},
        'http_clients': [{'tag': 'rules-download', 'version': 2, 'detour': 'rustine'}],
        'dns': {'servers': [{'type': 'local', 'tag': 'local-dns'}], 'final': 'local-dns'},
        'inbounds': [{
            'type': 'tun', 'tag': 'tun-in', 'interface_name': 'rustine-tun',
            'address': ['172.19.92.1/30'], 'auto_route': True, 'strict_route': True,
            'route_exclude_address': [net],
        }],
        'outbounds': [
            {'type': 'socks', 'tag': 'rustine', 'server': proxy_host, 'server_port': proxy_port, 'version': '5'},
            {'type': 'direct', 'tag': 'direct'},
            {'type': 'block', 'tag': 'block'},
        ],
        'route': {
            'auto_detect_interface': True,
            'rules': [
                {'action': 'sniff', 'timeout': '300ms'},
                {'protocol': 'dns', 'action': 'hijack-dns'},
                {'ip_is_private': True, 'action': 'route', 'outbound': 'direct'},
                {'domain_suffix': ['.ru', '.su', '.xn--p1ai'], 'action': 'route', 'outbound': 'direct'},
                {'rule_set': 'geoip-ru', 'action': 'route', 'outbound': 'direct'},
                # Rustine only handles TCP. Block non-DNS UDP rather than leak it.
                {'network': 'udp', 'action': 'route', 'outbound': 'block'},
            ],
            'rule_set': [{
                'type': 'remote', 'tag': 'geoip-ru', 'format': 'binary',
                'url': 'https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ru.srs',
                'update_interval': '1d',
                'http_client': 'rules-download',
            }],
            'final': 'rustine',
        },
        'experimental': {'cache_file': {'enabled': True, 'path': 'rustine-rule-cache.db'}},
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mode', choices=['pac', 'tun'], required=True)
    p.add_argument('--relay-ip', help='Public RU_RELAY IPv4/IPv6; required for TUN loop prevention')
    p.add_argument('--proxy-host', default='127.0.0.1')
    p.add_argument('--proxy-port', type=int, default=1080)
    p.add_argument('--output', type=pathlib.Path, required=True)
    args = p.parse_args()
    if args.mode == 'tun':
        if not args.relay_ip:
            p.error('--relay-ip is required for TUN to exclude RU_RELAY and prevent a routing loop')
        data = json.dumps(generate_tun(args.relay_ip, args.proxy_host, args.proxy_port), ensure_ascii=False, indent=2) + '\n'
    else:
        data = generate_pac(args.proxy_host, args.proxy_port)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(data, encoding='utf8')
    print('Generated:', args.output)


if __name__ == '__main__':
    main()
