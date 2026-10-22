import http.client
import threading
import unittest
from dashboard import make_server


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.server = make_server()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def request(self, method, path, body=None, headers=None):
        c = http.client.HTTPConnection('127.0.0.1', self.server.server_port)
        c.request(method, path, body, headers or {})
        r = c.getresponse(); result = (r.status, r.read()); c.close()
        return result

    def test_page_and_state(self):
        self.assertEqual(self.request('GET', '/')[0], 200)
        self.assertIn(b'packets', self.request('GET', '/api/state')[1])

    def test_no_cross_site_mutation(self):
        self.assertEqual(self.request('POST', '/api/stop', '')[0], 403)
        self.assertEqual(self.request('POST', '/api/stop', '', {'X-Logchecker-Token':self.server.token, 'Origin':'https://example.org'})[0], 403)

    def test_bad_upload(self):
        self.assertEqual(self.request('POST', '/api/pcap', b'not a capture', {'X-Logchecker-Token':self.server.token})[0], 400)

    def test_host_rejected(self):
        self.assertEqual(self.request('GET', '/api/state', headers={'Host':'example.org'})[0], 403)
