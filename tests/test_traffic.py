import unittest
from traffic import Analyzer, FIELDS, command, decode


def packet(**changes):
    p = dict(frame=1, time=1., size=60, src='192.0.2.1', dst='192.0.2.2',
             sport='40000', dport='443', transport='TCP', dns='', response=False,
             syn=False, ack=False, reset=False, tls=False)
    p.update(changes)
    return p


class TrafficTests(unittest.TestCase):
    def test_bidirectional_flow(self):
        a = Analyzer()
        a.feed(packet())
        self.assertIsNone(a.feed(packet(src='192.0.2.2', dst='192.0.2.1', sport='443', dport='40000')))
        self.assertEqual(a.summary()['tracked_flows'], 1)
        self.assertEqual(a.summary()['bytes'], 120)

    def test_bounded_memory(self):
        a = Analyzer(capacity=2)
        for i in range(10):
            a.feed(packet(dport=str(i)))
        self.assertEqual(len(a.flows), 2)
        self.assertEqual(a.evicted, 8)

    def test_syn_is_not_success(self):
        e = Analyzer().feed(packet(syn=True))
        self.assertIn('не подтверждает', e['note'])

    def test_dns_and_tls(self):
        self.assertIn('example.org', Analyzer().feed(packet(dns='example.org'))['explanation'])
        self.assertIn('зашифровано', Analyzer().feed(packet(tls=True))['note'])

    def test_ipv6_decode(self):
        fields = dict.fromkeys(FIELDS, '')
        fields.update({'frame.number':'2', 'frame.time_epoch':'1.5', 'frame.len':'80',
                       'ipv6.src':'::1', 'ipv6.dst':'::1', 'udp.srcport':'123', 'udp.dstport':'456'})
        fields['tcp.flags.syn'] = 'True'
        fields['tcp.flags.ack'] = 'False'
        p = decode([fields[f] for f in FIELDS])
        self.assertTrue(p['syn'])
        self.assertFalse(p['ack'])
        self.assertEqual(p['src'], '::1')
        self.assertEqual(p['transport'], 'UDP')
        with self.assertRaises(ValueError):
            decode(['broken'])

    def test_capture_args_no_shell(self):
        args = command('tshark', interface='lo', capture_filter='tcp port 443')
        self.assertEqual(args[args.index('-f')+1], 'tcp port 443')
        self.assertIn('-p', args)
        self.assertNotIn('-i', command('tshark', pcap='record.pcap'))
