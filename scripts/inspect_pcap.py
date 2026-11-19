#!/usr/bin/env python3
"""Minimal pcap sanity check: tests one captured TLS 1.3 handshake.
Not a DPI oracle or proof of blocking resistance. Supports tcpdump Ethernet PCAP.
"""
import argparse
import struct
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument("pcap", type=Path)
p.add_argument("--sni", default="relay.test")
a = p.parse_args()
data = a.pcap.read_bytes()
if len(data) < 24:
    raise SystemExit("FAIL: empty/invalid PCAP")
magic = data[:4]
if magic == b"\xd4\xc3\xb2\xa1":
    fmt = "<"
elif magic == b"\xa1\xb2\xc3\xd4":
    fmt = ">"
else:
    raise SystemExit("FAIL: unsupported PCAP format")
network = struct.unpack(fmt + "I", data[20:24])[0]
if network != 1:
    raise SystemExit(f"FAIL: expected Ethernet DLT=1, got {network}")
frames = []
offset = 24
while offset + 16 <= len(data):
    _, _, incl, _ = struct.unpack(fmt + "IIII", data[offset:offset + 16])
    offset += 16
    if incl <= 0 or offset + incl > len(data):
        raise SystemExit("FAIL: truncated PCAP record")
    frame = data[offset:offset + incl]
    offset += incl
    if len(frame) < 14 or frame[12:14] != b"\x08\x00":
        continue
    ipv4 = frame[14:]
    if len(ipv4) < 20 or ipv4[9] != 6:
        continue
    ip_len = (ipv4[0] & 15) * 4
    tcp = ipv4[ip_len:]
    if len(tcp) < 20:
        continue
    tcp_len = ((tcp[12] >> 4) & 15) * 4
    payload = tcp[tcp_len:]
    if payload:
        frames.append(payload)
wire = b"".join(frames)
# The client TLS ClientHello is a plaintext record and carries our configured SNI.
if not any(b"\x16\x03\x01" in part or b"\x16\x03\x03" in part for part in frames):
    raise SystemExit("FAIL: no TLS handshake record")
if a.sni.encode() not in wire:
    raise SystemExit(f"FAIL: ClientHello SNI {a.sni!r} not observed")
if not any(b"\x17\x03\x03" in part for part in frames):
    raise SystemExit("FAIL: no TLS application-data record")
if b"rustine-v1" in wire or b"RUSTINE_OK" in wire or b"test-only-32-character-secret-change" in wire:
    raise SystemExit("FAIL: cleartext application marker/secret on wire")
print(f"PASS: TLS handshake, visible SNI {a.sni}, encrypted TLS application data; no plaintext marker")
print("NOTE: this is a packet smoke test, not proof of DPI evasion")
