import unittest
from logwatch import analyze


def ssh(second, action='Failed password', ip='192.0.2.1'):
    return f'Oct 22 10:00:{second:02} host sshd[1]: {action} for user from {ip} port 22 ssh2'


class DetectionTests(unittest.TestCase):
    def test_failures_and_success(self):
        result = analyze([ssh(i) for i in range(5)] + [ssh(6, 'Accepted publickey')], 2026)
        self.assertEqual([f['rule'] for f in result['findings']], ['ssh_brute_force', 'success_after_failures'])
        self.assertEqual(result['findings'][1]['evidence'], list(range(1, 7)))

    def test_window_and_ip_isolation(self):
        result = analyze([ssh(i * 10) for i in range(5)] + [ssh(41, 'Accepted password', '192.0.2.2')], 2026, window=5)
        self.assertEqual(result['findings'], [])

    def test_web_and_malformed(self):
        lines = [f'192.0.2.1 - - [22/Oct/2026:10:00:0{i} +0000] "GET /.env HTTP/1.1" 404 10' for i in range(5)]
        result = analyze(lines + ['garbage'], 2026)
        self.assertEqual(result['findings'][0]['rule'], 'suspicious_paths')
        self.assertEqual(result['skipped'], 1)

    def test_sort_and_no_false_alert(self):
        result = analyze([ssh(9), ssh(1), ssh(5, 'Accepted password')], 2026)
        self.assertEqual(result['findings'], [])
        self.assertEqual([e['line'] for e in result['timeline']], [2, 3, 1])

if __name__ == '__main__':
    unittest.main()
