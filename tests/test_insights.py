import unittest
from test_traffic import packet
from traffic import Analyzer


class InsightsTests(unittest.TestCase):
    def test_tls_collapsed_and_counts(self):
        a=Analyzer()
        self.assertIsNotNone(a.feed(packet(tls=True)))
        for i in range(100):
            self.assertIsNone(a.feed(packet(tls=True, frame=i+2)))
        f=a.insights.snapshot()['conversations'][0]
        self.assertEqual(f['packets'],101)
        self.assertEqual(f['bytes'],6060)
        self.assertEqual(f['evidence']['tls'],1)

    def test_reverse_direction_and_reset(self):
        a=Analyzer();a.feed(packet(syn=True))
        a.feed(packet(src='192.0.2.2',dst='192.0.2.1',sport='443',dport='40000',reset=True,frame=2))
        f=a.insights.snapshot()['conversations'][0]
        self.assertEqual((f['sent'],f['received']),(60,60))
        self.assertTrue(f['attention']);self.assertEqual(f['evidence']['reset'],2)

    def test_scan_threshold_retries_and_window(self):
        a=Analyzer()
        for i in range(30): a.feed(packet(syn=True,frame=i+1))
        self.assertEqual(a.insights.snapshot()['alerts'],[])
        for i in range(19): a.feed(packet(syn=True,dport=str(i),frame=100+i,time=2))
        alerts=a.insights.snapshot()['alerts']
        self.assertEqual(len(alerts),1)
        self.assertEqual(len(alerts[0]['ports']),20)
        b=Analyzer()
        for i in range(25): b.feed(packet(syn=True,dport=str(i),time=i*11))
        self.assertFalse(b.insights.snapshot()['alerts'])

    def test_hosts_not_combined_and_memory_bounded(self):
        a=Analyzer(capacity=2)
        for i in range(25): a.feed(packet(syn=True,dport=str(i),dst=f'192.0.2.{i+3}'))
        self.assertFalse(a.insights.snapshot()['alerts'])
        self.assertEqual(len(a.insights.flows),2)

    def test_dns_not_attributed_to_other_flow(self):
        a=Analyzer();a.feed(packet(dns='example.org',dport='53',transport='UDP'))
        a.feed(packet(tls=True))
        self.assertEqual(a.insights.snapshot()['conversations'][0]['dns'],[])
