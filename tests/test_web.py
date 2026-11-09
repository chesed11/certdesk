"""Local HTTP security and integration tests; no real certificate changes."""
import http.client
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import server

class WebTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        server.DB = Path(cls.temp.name) / 'test.db'
        server.init_db()
        cls.http = server.ThreadingHTTPServer(('127.0.0.1', 0), server.Handler)
        cls.thread = threading.Thread(target=cls.http.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.http.shutdown()
        cls.http.server_close()
        cls.thread.join()
        cls.temp.cleanup()

    def req(self, method, path, data=None, cookie=None, origin=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.http.server_port, timeout=5)
        headers = {'Host': '127.0.0.1:8765', 'Content-Type': 'application/json'}
        if cookie: headers['Cookie'] = cookie
        if origin: headers['Origin'] = origin
        conn.request(method, path, body=json.dumps(data).encode() if data is not None else None, headers=headers)
        response = conn.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        conn.close()
        return result

    def test_auth_and_isolation(self):
        self.assertEqual(self.req('GET', '/')[0], 200)
        self.assertEqual(self.req('GET', '/api/overview')[0], 401)
        self.assertEqual(self.req('POST', '/api/session', {'token':'错误'})[0], 401)
        self.assertEqual(self.req('POST', '/api/session', {'token':server.ACCESS_CODE}, origin='https://attacker.example')[0], 403)
        code, headers, _ = self.req('POST', '/api/session', {'token':server.ACCESS_CODE})
        self.assertEqual(code, 200)
        cookie = headers['Set-Cookie'].split(';')[0]
        self.assertEqual(self.req('GET', '/api/overview', cookie=cookie)[0], 200)
        self.assertEqual(self.req('POST', '/api/automation/renew', {}, cookie=cookie)[0], 404)
        self.assertEqual(self.req('POST', '/api/automation', {'enabled':True}, cookie=cookie)[0], 404)
        self.assertEqual(self.req('POST', '/api/automation/check', {'domain':'x:443'}, cookie=cookie)[0], 400)
        original_connect = server.automation.socket.create_connection
        def connection(address, *args, **kwargs):
            if address[0] == 'example.com': raise OSError('offline')
            return original_connect(address, *args, **kwargs)
        with patch.object(server.automation.socket, 'create_connection', side_effect=connection):
            code, _, body = self.req('POST', '/api/automation/check', {'domain':'example.com'}, cookie=cookie)
            self.assertEqual(code, 200)
            self.assertFalse(json.loads(body)['ok'])
        self.assertEqual(self.req('GET', '/api/system-status', cookie=cookie)[0], 200)
        self.assertEqual(self.req('DELETE', '/api/session', cookie=cookie)[0], 200)

if __name__ == '__main__': unittest.main()
