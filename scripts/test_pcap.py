#!/usr/bin/env python3
"""Independent offline tests for the PCAP/TLS parser (no Docker required)."""
import struct
import unittest
from inspect_pcap import analyze


def tls_client_hello(sni):
    name = sni.encode()
    names = b"\x00" + len(name).to_bytes(2, "big") + name
    ext = b"\x00\x00" + (2 + len(names)).to_bytes(2, "big") + len(names).to_bytes(2, "big") + names
    body = (b"\x03\x03" + bytes(32) + b"\x00" + b"\x00\x02\x13\x01"
            + b"\x01\x00" + len(ext).to_bytes(2, "big") + ext)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def ethernet_tcp(src, dst, sport, dport, seq, payload):
    tcp = struct.pack("!HHIIHHHH", sport, dport, seq, 0, 5 << 12, 0, 0, 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, len(tcp)+20, 1, 0, 64, 6, 0, src, dst)
    return b"\x00" * 12 + b"\x08\x00" + ip + tcp


def pcap(parts):
    raw = bytearray(b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1))
    for frame in parts:
        raw.extend(struct.pack("<IIII", 0, 0, len(frame), len(frame)))
        raw.extend(frame)
    return bytes(raw)


class PcapTests(unittest.TestCase):
    src, dst = b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02"

    def connection(self, sni="relay.test", split=19, exposed=b""):
        hello = tls_client_hello(sni)
        app = b"\x17\x03\x03\x00\x04" + b"xxxx"
        return pcap([
            ethernet_tcp(self.src, self.dst, 50000, 8443, 1000, hello[:split]),
            ethernet_tcp(self.src, self.dst, 50000, 8443, 1000+split, hello[split:]+app+exposed),
            ethernet_tcp(self.dst, self.src, 8443, 50000, 9000, app),
        ])

    def test_split_tcp_segment(self):
        self.assertIn("relay.test", analyze(self.connection(), "relay.test"))

    def test_unexpected_sni(self):
        with self.assertRaisesRegex(ValueError, "observed"):
            analyze(self.connection("wrong.test"), "relay.test")

    def test_reject_cleartext_secret(self):
        with self.assertRaisesRegex(ValueError, "plaintext"):
            analyze(self.connection(exposed=b"RUSTINE_OK"), "relay.test")

    def test_reject_raw_fake_sni_without_hello(self):
        data = pcap([ethernet_tcp(self.src, self.dst, 50000, 8443, 1000,
                                 b"relay.test" + b"\x17\x03\x03\x00\x01x")])
        with self.assertRaisesRegex(ValueError, "complete TLS"):
            analyze(data, "relay.test")


if __name__ == "__main__":
    unittest.main()
