import os, sys, json, threading, tempfile, socket
from http.server import BaseHTTPRequestHandler, HTTPServer
import pytest

def free_port():
    s = socket.socket(); s.bind(('127.0.0.1', 0)); p = s.getsockname()[1]; s.close(); return p

# --- stub Claude API (records requests) ---
AI_CALLS = []
class Stub(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers['content-length'])))
        AI_CALLS.append({'headers': dict(self.headers), 'body': body})
        out = json.dumps({'content': [{'type': 'text', 'text': 'Stub answer citing clause 6.1 (p.3).'}], 'usage': {'input_tokens': 120, 'output_tokens': 30}}).encode()
        self.send_response(200); self.send_header('content-type', 'application/json'); self.end_headers(); self.wfile.write(out)
    def log_message(self, *a): pass
AI_PORT = free_port(); threading.Thread(target=HTTPServer(('127.0.0.1', AI_PORT), Stub).serve_forever, daemon=True).start()

# --- local SMTP sink ---
from aiosmtpd.controller import Controller
MAILS = []
class Sink:
    async def handle_DATA(self, server, session, envelope):
        MAILS.append({'to': envelope.rcpt_tos, 'data': envelope.content.decode('utf8', 'replace')}); return '250 OK'
SMTP_PORT = free_port(); _smtp = Controller(Sink(), hostname='127.0.0.1', port=SMTP_PORT); _smtp.start()

tmp = tempfile.mkdtemp()
os.environ.update({'CAT_DATA_DIR': tmp, 'CAT_RUN_JOBS': '0', 'ANTHROPIC_API_KEY': 'test-key', 'ANTHROPIC_BASE_URL': 'http://127.0.0.1:%d' % AI_PORT,
                   'SMTP_HOST': '127.0.0.1', 'SMTP_PORT': str(SMTP_PORT), 'SMTP_TLS': '0'})
if not os.environ.get('DATABASE_URL'):
    os.environ['DATABASE_URL'] = 'sqlite:///' + os.path.join(tmp, 'test.db')
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from cat_server import cli  # noqa: E402  (creates tables)
from cat_server.main import app  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
PW = 'Sample-2026-demo'
cli.seed_sample(PW)

@pytest.fixture
def login():
    def _l(email, pw=PW):
        c = TestClient(app); r = c.post('/api/auth/login', json={'email': email, 'password': pw}); assert r.status_code == 200, r.text
        c.headers.update({'x-cat-request': '1'}); return c
    return _l

@pytest.fixture
def ai_calls(): return AI_CALLS

@pytest.fixture
def mails(): return MAILS
