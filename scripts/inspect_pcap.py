#!/usr/bin/env python3
"""Offline TLS sanity check for Rustine's client-to-relay TCP connection.

Checks a parsed ClientHello SNI extension and TLS application records in one
TCP conversation. Not a DPI bypass test and not an active-probing defense.
Only classic Ethernet PCAP, IPv4/IPv6 (no IPv6 extension headers) are supported.
"""
import argparse
from collections import defaultdict
from pathlib import Path
import struct

MAX_CAPTURE = 32 * 1024 * 1024
MAX_STREAM = 2 * 1024 * 1024
FORBIDDEN = (b"rustine-v1", b"RUSTINE_OK", b"test-relay-psk-32-character-secret",
             b"test-exit-psk-32-character-secret")


def tcp_payload(packet):
    if len(packet) < 14:
        return None
    cursor = 12
    ethertype = int.from_bytes(packet[cursor:cursor+2], "big")
    cursor = 14
    while ethertype in (0x8100, 0x88A8):
        if len(packet) < cursor + 4:
            return None
        ethertype = int.from_bytes(packet[cursor+2:cursor+4], "big")
        cursor += 4
    if ethertype == 0x0800:
        ip = packet[cursor:]
        if len(ip) < 20 or ip[0] >> 4 != 4:
            return None
        header_len = (ip[0] & 15) * 4
        total_len = int.from_bytes(ip[2:4], "big")
        if header_len < 20 or total_len < header_len or len(ip) < total_len:
            return None
        if ip[9] != 6 or int.from_bytes(ip[6:8], "big") & 0x1FFF:
            return None
        src, dst = ip[12:16], ip[16:20]
        tcp = ip[header_len:total_len]
    elif ethertype == 0x86DD:
        ip = packet[cursor:]
        if len(ip) < 40 or ip[0] >> 4 != 6 or ip[6] != 6:
            return None
        total_len = int.from_bytes(ip[4:6], "big") + 40
        if len(ip) < total_len:
            return None
        src, dst = ip[8:24], ip[24:40]
        tcp = ip[40:total_len]
    else:
        return None
    if len(tcp) < 20:
        return None
    header_len = (tcp[12] >> 4) * 4
    if header_len < 20 or header_len > len(tcp):
        return None
    payload = tcp[header_len:]
    if not payload:
        return None
    src_port, dst_port = struct.unpack("!HH", tcp[:4])
    seq = int.from_bytes(tcp[4:8], "big")
    return (src, src_port, dst, dst_port), seq, payload


def captured_flows(data):
    if len(data) < 24 or len(data) > MAX_CAPTURE:
        raise ValueError("empty or too large PCAP")
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise ValueError("unsupported PCAP header")
    if struct.unpack(endian + "I", data[20:24])[0] != 1:
        raise ValueError("PCAP must have Ethernet link type")
    segments = defaultdict(list)
    offset = 24
    while offset + 16 <= len(data):
        _, _, cap_len, _ = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        if cap_len == 0 or offset + cap_len > len(data):
            raise ValueError("truncated PCAP packet")
        result = tcp_payload(data[offset:offset + cap_len])
        offset += cap_len
        if result:
            key, seq, payload = result
            segments[key].append((seq, payload))
    if offset != len(data):
        raise ValueError("trailing malformed PCAP bytes")
    streams = {}
    for key, parts in segments.items():
        parts.sort(key=lambda part: part[0])
        wire = bytearray()
        expected = parts[0][0]
        for seq, payload in parts:
            # Ignore duplicates/retransmissions; stop at missing TCP sequence bytes.
            if seq > expected:
                break
            overlap = expected - seq
            if overlap < len(payload):
                wire.extend(payload[overlap:])
                expected = seq + len(payload)
            if len(wire) > MAX_STREAM:
                raise ValueError("TCP stream exceeds safety limit")
        streams[key] = bytes(wire)
    return streams


def tls_records(wire):
    offset = 0
    while offset + 5 <= len(wire):
        kind = wire[offset]
        version = wire[offset+1:offset+3]
        length = int.from_bytes(wire[offset+3:offset+5], "big")
        if kind not in (20, 21, 22, 23) or version not in (b"\x03\x01", b"\x03\x03"):
            break
        if length > 18432 or offset + 5 + length > len(wire):
            break
        yield kind, wire[offset+5:offset+5+length]
        offset += 5 + length


def hello_sni(body):
    """Extract the DNS-name extension from a TLS ClientHello body only."""
    try:
        if len(body) < 35:
            return None
        p = 34  # legacy version (2) + random (32)
        sid_len = body[p]
        p += 1 + sid_len
        cipher_len = int.from_bytes(body[p:p+2], "big")
        p += 2 + cipher_len
        compression_len = body[p]
        p += 1 + compression_len
        ext_len = int.from_bytes(body[p:p+2], "big")
        p += 2
        end = p + ext_len
        if end > len(body):
            return None
        while p + 4 <= end:
            ext_type = int.from_bytes(body[p:p+2], "big")
            size = int.from_bytes(body[p+2:p+4], "big")
            p += 4
            if p + size > end:
                return None
            if ext_type == 0:
                sni = body[p:p+size]
                if len(sni) < 5 or int.from_bytes(sni[:2], "big") != len(sni)-2:
                    return None
                if sni[2] != 0:
                    return None
                name_len = int.from_bytes(sni[3:5], "big")
                if 5 + name_len != len(sni):
                    return None
                return sni[5:].decode("ascii")
            p += size
    except (IndexError, UnicodeDecodeError):
        return None
    return None


def client_hellos(wire):
    handshake = b"".join(payload for kind, payload in tls_records(wire) if kind == 22)
    offset = 0
    while offset + 4 <= len(handshake):
        kind = handshake[offset]
        length = int.from_bytes(handshake[offset+1:offset+4], "big")
        offset += 4
        if length > len(handshake) - offset:
            break
        if kind == 1:
            yield hello_sni(handshake[offset:offset+length])
        offset += length


def analyze(data, expected_sni):
    streams = captured_flows(data)
    if not streams:
        raise ValueError("no TCP payload captured")
    if any(marker in payload for payload in streams.values() for marker in FORBIDDEN):
        raise ValueError("plaintext protocol marker or test secret visible on wire")
    actual_names = []
    for (src, src_port, dst, dst_port), wire in streams.items():
        names = list(client_hellos(wire))
        actual_names.extend(name for name in names if name)
        if expected_sni not in names:
            continue
        reverse = streams.get((dst, dst_port, src, src_port), b"")
        encrypted = any(kind == 23 for kind, _ in tls_records(wire))
        encrypted |= any(kind == 23 for kind, _ in tls_records(reverse))
        if encrypted:
            return f"TLS ClientHello SNI {expected_sni!r}, encrypted application records verified"
    raise ValueError(f"no complete TLS conversation with SNI={expected_sni!r} and application records; observed={actual_names!r}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("--sni", required=True)
    args = parser.parse_args()
    try:
        result = analyze(args.pcap.read_bytes(), args.sni)
    except (ValueError, OSError) as exc:
        raise SystemExit(f"FAIL: {exc}") from exc
    print(f"PASS: {result}")
    print("NOTE: structural TLS smoke test only; not proof of DPI evasion")


if __name__ == "__main__":
    main()
