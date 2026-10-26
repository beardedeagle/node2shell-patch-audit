import http.server
import io
import json
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import verify_service


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_POST(self):
        self.rfile.read(int(self.headers['Content-Length']))
        self.server.clients.add(self.client_address)
        self.server.requests += 1
        body = json.dumps({'pid': 123, 'text': self.server.text}).encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()
        if self.server.requests >= 12:
            self.server.traffic_ready.set()

    def finish(self):
        super().finish()
        self.server.connection_closed.set()

    def log_message(self, *args):
        pass


class ServiceTrafficTests(unittest.TestCase):
    def setUp(self):
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.addCleanup(self.server.server_close)
        self.server.clients = set()
        self.server.requests = 0
        self.server.text = 'node2shell benign service acceptance'
        self.server.traffic_ready = threading.Event()
        self.server.connection_closed = threading.Event()
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(self.server.shutdown)
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.service = {'pid': 123, 'port': self.server.server_port,
                        'payload': b'fixture', 'binary': str(self.root / 'node')}

    def test_traffic_reuses_connection_and_closes_it(self):
        def audit_run(*args, **kwargs):
            self.assertTrue(self.server.traffic_ready.wait(5), 'traffic stopped early')
            report = {'exit_status': 0, 'verdict': 'UNKNOWN', 'runtimes': [],
                      'issues': ['Audit mocked for traffic test']}
            return SimpleNamespace(returncode=0, stdout=json.dumps({'reports': [report]}))

        with patch.object(verify_service.subprocess, 'run', side_effect=audit_run), redirect_stdout(io.StringIO()):
            verify_service.check_services(self.root, [self.service], {}, {}, 'Connection reuse')
        self.assertEqual(len(self.server.clients), 1, 'requests opened fresh TCP connections')
        self.assertTrue(self.server.connection_closed.wait(5), 'connection leaked after audit')

    def test_invalid_response_fails_and_closes_connection(self):
        self.server.text = 'unexpected response'
        with patch.object(verify_service.subprocess, 'run') as audit_run, self.assertRaises(AssertionError):
            verify_service.check_services(self.root, [self.service], {}, {}, 'Invalid response')
        audit_run.assert_not_called()
        self.assertTrue(self.server.connection_closed.wait(5), 'connection leaked after failure')


if __name__ == '__main__':
    unittest.main()
