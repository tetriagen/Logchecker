"""Real TShark decoding of synthetic local fixtures; no network access."""
import csv
import io
import shutil
import ssl
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from traffic import Analyzer, command, decode


def example_pcap():
    ethernet = bytes.fromhex('00112233445566778899aabb0800')
    def ip(payload, protocol, src, dst):
        return ethernet + struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(payload), 0, 0, 64,
                                      protocol, 0, src, dst) + payload
    client, server, dns_server = bytes([192,0,2,1]), bytes([192,0,2,2]), bytes([192,0,2,53])
    def tcp(port, payload=b'', syn=False):
        header = struct.pack('!HHIIBBHHH', 40000, port, 0 if syn else 1, 0,
                             0x50, 2 if syn else 0x18, 65535, 0, 0)
        return ip(header+payload, 6, client, server)
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    client_ssl = ssl.create_default_context().wrap_bio(incoming, outgoing, server_side=False,
                                                       server_hostname='secure.example.test')
    try:
        client_ssl.do_handshake()
    except ssl.SSLWantReadError:
        pass
    name = b'\x07example\x04test\x00'
    dns = (struct.pack('!6H', 1, 0x8180, 1, 1, 0, 0) + name + struct.pack('!HH', 1, 1) +
           b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 30, 4) + server)
    udp = struct.pack('!4H', 53, 50000, 8+len(dns), 0) + dns
    packets = [ip(udp, 17, dns_server, client), tcp(80, syn=True),
               tcp(80, b'GET / HTTP/1.1\r\nHost: web.example.test\r\n\r\n'),
               tcp(443, syn=True), tcp(443, outgoing.read())]
    data = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    for number, packet in enumerate(packets):
        data += struct.pack('<IIII', 1700000000+number, 0, len(packet), len(packet)) + packet
    return data


@unittest.skipUnless(shutil.which('tshark'), 'TShark is not installed')
class IdentityIntegrationTests(unittest.TestCase):
    def test_actual_tshark_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'identities.pcap'
            path.write_bytes(example_pcap())
            result = subprocess.run(command(shutil.which('tshark'), pcap=str(path)),
                                    capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        analyzer = Analyzer()
        for row in csv.reader(io.StringIO(result.stdout), delimiter='\t'):
            analyzer.feed(decode(row))
        groups = analyzer.insights.snapshot()['conversations']
        names = {(s['name'], s['source']) for f in groups for s in f['sites']}
        self.assertIn(('secure.example.test', 'TLS SNI'), names)
        self.assertIn(('web.example.test', 'HTTP Host'), names)
        self.assertEqual(analyzer.packets, 5)
        self.assertTrue(analyzer.insights.dns_hints.entries)
        self.assertTrue(all(not f['applications'] for f in groups))
