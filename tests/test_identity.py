import time
import unittest
from unittest.mock import patch
from identity import DNSHints, SocketOwners, hostname, parse_sockets
from traffic import Analyzer, FIELDS, decode
from dashboard import Session
from test_traffic import packet


def answer(**kwargs):
    p = packet(src='192.0.2.53', dst='192.0.2.1', sport='53', dport='50000',
               transport='UDP', response=True, dns='example.org', dns_owner='example.org',
               dns_type='1', dns_answers='1', dns_rcode='0', dns_a='192.0.2.2', dns_ttl='30')
    p.update(kwargs)
    return p


class IdentityTests(unittest.TestCase):
    def test_sni_and_host_evidence(self):
        a = Analyzer()
        a.feed(packet(sni='Example.ORG', tls=True, frame=10))
        a.feed(packet(http_host='other.test:8080', frame=11))
        f = a.insights.snapshot()['conversations'][0]
        self.assertEqual([(s['name'], s['source'], s['frame']) for s in f['sites']],
                         [('example.org', 'TLS SNI', 10), ('other.test', 'HTTP Host', 11)])
        self.assertFalse(f['applications'])

    def test_no_sni_does_not_guess_by_port(self):
        a = Analyzer(); a.feed(packet(tls=True))
        f = a.insights.snapshot()['conversations'][0]
        self.assertEqual((f['sites'], f['dns_candidates']), ([], []))

    def test_unsafe_names_and_ip_literals(self):
        for value in ('<script>', 'a\n.test', 'a.test/path', '192.0.2.1', '[::1]', 'a'*64+'.org'):
            self.assertEqual(hostname(value), '')
        self.assertEqual(hostname('xn--e1afmkfd.xn--p1ai'), 'xn--e1afmkfd.xn--p1ai')

    def test_dns_scope_expiry_and_ambiguity(self):
        d = DNSHints(); d.observe(answer())
        self.assertEqual(d.lookup(packet(time=2))[0]['confidence'], 'candidate')
        self.assertFalse(d.lookup(packet(time=2, src='192.0.2.9')))
        self.assertFalse(d.lookup(packet(time=31)))
        d.observe(answer(dns='other.org', dns_owner='other.org', frame=2))
        self.assertEqual(len(d.lookup(packet(time=2))), 2)

    def test_dns_rejects_weak_evidence(self):
        for changes in ({'response':False}, {'dns_ttl':'0'}, {'dns_rcode':'3'},
                        {'dns_answers':'2'}, {'dns_owner':'unrelated.org'}, {'dns_type':'5'}):
            d = DNSHints(); d.observe(answer(**changes))
            self.assertFalse(d.lookup(packet(time=2)))

    def test_dns_direct_name_wins_and_expiry_updates(self):
        a = Analyzer(); a.feed(answer()); a.feed(packet(time=2))
        self.assertTrue(a.insights.snapshot()['conversations'][0]['dns_candidates'])
        a.feed(packet(time=32))
        self.assertFalse(a.insights.snapshot()['conversations'][0]['dns_candidates'])
        a.feed(packet(time=33, sni='explicit.test'))
        self.assertEqual(a.insights.snapshot()['conversations'][0]['sites'][0]['name'], 'explicit.test')

    def test_ipv6_dns_and_bounded_cache(self):
        d = DNSHints(capacity=1)
        d.observe(answer(dns_type='28', dns_aaaa='2001:db8::2'))
        self.assertTrue(d.lookup(packet(time=2, dst='2001:db8::2')))
        d.observe(answer(dns='new.test', dns_owner='new.test'))
        self.assertEqual(len(d.entries), 1)
        d.observe(packet(time=0))
        self.assertFalse(d.entries)

    def test_ss_exact_match_and_stale_sample(self):
        s = SocketOwners()
        s.table = parse_sockets('tcp ESTAB 0 0 192.0.2.1:40000 192.0.2.2:443 users:(("firefox",pid=123,fd=8))')
        s.sampled = 100
        self.assertEqual(s.lookup(packet(time=100))[0]['name'], 'firefox')
        self.assertFalse(s.lookup(packet(time=103)))
        self.assertFalse(s.lookup(packet(time=100, dst='192.0.2.3')))
        self.assertTrue(s.lookup(packet(time=100, src='192.0.2.2', dst='192.0.2.1', sport='443', dport='40000')))

    def test_ipv6_multiple_owners_and_wildcards(self):
        t = parse_sockets('tcp ESTAB 0 0 [::1]:1000 [::1]:2000 users:(("python3",pid=1,fd=3),("worker",pid=2,fd=4))\n'
                          'udp UNCONN 0 0 0.0.0.0:1000 0.0.0.0:* users:(("x",pid=3,fd=5))')
        self.assertEqual(len(t), 1)
        self.assertEqual(len(next(iter(t.values()))), 2)

    def test_process_failure_is_graceful(self):
        with patch('identity.shutil.which', return_value=None):
            s = SocketOwners(); s.refresh()
        self.assertEqual(s.table, {})
        self.assertIn('недоступны', s.status)

    def test_decode_fields(self):
        fields = dict.fromkeys(FIELDS, '')
        fields.update({'frame.number':'1', 'frame.time_epoch':'1', 'frame.len':'100',
                       'tls.handshake.extensions_server_name':'example.org', 'http.host':'other.test'})
        p = decode([fields[f] for f in FIELDS])
        self.assertEqual((p['sni'], p['http_host']), ('example.org', 'other.test'))

    def test_pcap_never_starts_process_lookup(self):
        with patch('dashboard.SocketOwners') as owners, patch('dashboard.subprocess.Popen', side_effect=OSError('fixture')):
            s = Session(); s.run('tshark', None, '/tmp/logchecker-nonexistent-test.pcap', 1)
            owners.assert_not_called()
        self.assertEqual(s.snapshot()['state'], 'error')
