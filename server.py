#!/usr/bin/env python3
"""Local certificate metadata tracker. No keys are collected or processed."""
import json
import mimetypes
import re
import sqlite3
import automation
import secrets
from http.cookies import SimpleCookie, CookieError
from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

ROOT = Path(__file__).resolve().parent
DB = ROOT / 'data' / 'certificates.db'
HOST, PORT = '127.0.0.1', 8765
FIELDS = ('name', 'domain', 'issuer', 'expires_on', 'owner', 'environment', 'location', 'notes')
MAX_BODY = 32768
ACCESS_CODE = secrets.token_urlsafe(32)
SESSION_TOKEN = secrets.token_urlsafe(32)
STATUS_FILE = Path('/var/lib/certdesk/status.json')

@contextmanager
def connect():
    db = sqlite3.connect(DB, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    try:
        with db:
            yield db
    finally:
        db.close()

def init_db():
    DB.parent.mkdir(parents=True, exist_ok=True)
    with connect() as db:
        db.execute('''CREATE TABLE IF NOT EXISTS certificates (
          id INTEGER PRIMARY KEY, name TEXT NOT NULL, domain TEXT NOT NULL, issuer TEXT NOT NULL,
          expires_on TEXT NOT NULL, owner TEXT NOT NULL, environment TEXT NOT NULL,
          location TEXT NOT NULL, notes TEXT NOT NULL DEFAULT '')''')
        db.execute('''CREATE TABLE IF NOT EXISTS events (
          id INTEGER PRIMARY KEY, certificate_id INTEGER NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
          event_type TEXT NOT NULL, notes TEXT NOT NULL, created_at TEXT NOT NULL)''')
        db.execute('CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
        if not db.execute("SELECT 1 FROM settings WHERE key='seeded'").fetchone():
            today = date.today()
            demos = [
                ('官网 HTTPS（演示）', 'www.example.com', "Let's Encrypt", (today + timedelta(days=5)).isoformat(), '平台运维', '生产', 'Nginx / web-01', '演示数据，请替换为真实台账。'),
                ('支付网关（演示）', 'pay.example.com', 'DigiCert', (today + timedelta(days=21)).isoformat(), '支付团队', '生产', 'Ingress / prod', '需在维护窗口轮换。'),
                ('内部 API（演示）', 'api.internal.example', 'Internal CA', (today + timedelta(days=79)).isoformat(), '基础设施', '内部', 'Kubernetes / api', ''),
                ('旧测试服务（演示）', 'legacy.example.com', 'Internal CA', (today - timedelta(days=3)).isoformat(), '研发团队', '测试', 'VM / test-01', '请确认测试服务是否仍在使用。'),
            ]
            db.executemany('INSERT INTO certificates(name,domain,issuer,expires_on,owner,environment,location,notes) VALUES (?,?,?,?,?,?,?,?)', demos)
            db.execute('INSERT INTO events(certificate_id,event_type,notes,created_at) VALUES (?,?,?,?)', (1,'检查','演示记录：已确认负责人与部署位置。', datetime.now(timezone.utc).isoformat(timespec='seconds')))
            db.execute("INSERT INTO settings VALUES ('seeded','1')")

def cert(row):
    item = dict(row)
    days = (date.fromisoformat(item['expires_on']) - date.today()).days
    item['days_remaining'] = days
    item['status'] = 'expired' if days < 0 else 'critical' if days <= 7 else 'warning' if days <= 30 else 'healthy'
    return item

def validate_text(v, field, required=False, limit=1000):
    if not isinstance(v, str):
        raise ValueError(field + ' 必须为文本')
    v = v.strip()
    if required and not v:
        raise ValueError(field + ' 不能为空')
    if len(v) > limit:
        raise ValueError(field + ' 内容过长')
    if re.search(r'-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----', v, re.I):
        raise ValueError('禁止提交私钥')
    return v

def validate_certificate(obj):
    if not isinstance(obj, dict):
        raise ValueError('请求必须是对象')
    if set(obj) - set(FIELDS):
        raise ValueError('存在不支持的字段')
    out = {f: validate_text(obj.get(f, ''), f, f in ('name','domain','expires_on'), 2000 if f == 'notes' else 255) for f in FIELDS}
    try:
        parsed = date.fromisoformat(out['expires_on'])
        if parsed.isoformat() != out['expires_on']:
            raise ValueError()
    except ValueError:
        raise ValueError('expires_on 必须为 YYYY-MM-DD 日期')
    return out

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print('%s %s' % (self.address_string(), fmt % args))

    def trusted(self):
        host = self.headers.get('Host', '').lower()
        origin = self.headers.get('Origin')
        return host in ('127.0.0.1:8765', 'localhost:8765') and (not origin or origin in ('http://127.0.0.1:8765', 'http://localhost:8765'))

    def authenticated(self):
        try:
            cookies = SimpleCookie(self.headers.get('Cookie', ''))
            value = cookies['certdesk_session'].value if 'certdesk_session' in cookies else ''
            return secrets.compare_digest(value, SESSION_TOKEN)
        except (CookieError, TypeError):
            return False

    def reply(self, status, data, cookie=None):
        payload = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type','application/json; charset=utf-8')
        self.send_header('Content-Length',str(len(payload)))
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        if cookie:
            self.send_header('Set-Cookie', cookie)
        self.end_headers()
        self.wfile.write(payload)

    def body(self):
        if self.headers.get_content_type() != 'application/json':
            raise ValueError('Content-Type 必须为 application/json')
        try:
            length = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            raise ValueError('无效的请求长度')
        if length <= 0 or length > MAX_BODY:
            raise ValueError('请求为空或过大')
        try:
            return json.loads(self.rfile.read(length).decode('utf-8'))
        except (ValueError, UnicodeDecodeError):
            raise ValueError('无效的 JSON')

    def do_GET(self):
        if not self.trusted():
            return self.reply(403, {'error':'禁止访问'})
        uri = urlparse(self.path)
        if uri.path.startswith('/api/') and not self.authenticated():
            return self.reply(401, {'error':'请先输入本次启动的访问码'})
        if uri.path == '/api/session':
            return self.reply(200, {'ok':True})
        if uri.path == '/api/system-status':
            try:
                if STATUS_FILE.stat().st_size > 16384: raise ValueError('status too large')
                status = json.loads(STATUS_FILE.read_text(encoding='utf-8'))
                if not isinstance(status, dict): raise ValueError('invalid status')
                return self.reply(200, {key: str(status.get(key, ''))[:1000] for key in ('status','summary','updated_at')})
            except (OSError, ValueError, UnicodeDecodeError):
                return self.reply(200, {'status':'unconfigured','summary':'尚无系统任务执行记录，或当前用户无读取权限。','updated_at':''})
        with connect() as db:
            if uri.path == '/api/certificates':
                return self.reply(200, [cert(r) for r in db.execute('SELECT * FROM certificates ORDER BY expires_on,id')])
            if uri.path == '/api/overview':
                entries = [cert(r) for r in db.execute('SELECT * FROM certificates')]
                return self.reply(200, {'total':len(entries), **{s: sum(e['status'] == s for e in entries) for s in ('expired','critical','warning','healthy')}})
            if uri.path == '/api/events':
                cid = parse_qs(uri.query).get('certificate_id', [None])[0]
                query = 'SELECT e.*, c.name AS certificate_name FROM events e JOIN certificates c ON c.id=e.certificate_id'
                params = ()
                if cid is not None:
                    if not cid.isdigit(): return self.reply(400, {'error':'无效的证书 ID'})
                    query += ' WHERE e.certificate_id=?'
                    params = (int(cid),)
                return self.reply(200, [dict(r) for r in db.execute(query + ' ORDER BY e.id DESC LIMIT 500',params)])
        if uri.path.startswith('/api/'):
            return self.reply(404, {'error':'未找到'})
        static = {'/':'index.html', '/index.html':'index.html', '/app.js':'app.js', '/style.css':'style.css', '/styles.css':'styles.css'}
        filename = static.get(uri.path)
        if not filename or not (ROOT / 'static' / filename).is_file():
            return self.reply(404, {'error':'未找到'})
        payload = (ROOT / 'static' / filename).read_bytes()
        self.send_response(200)
        content_type = {'html': 'text/html', 'css': 'text/css', 'js': 'application/javascript'}.get(filename.rsplit('.', 1)[-1], 'application/octet-stream')
        self.send_header('Content-Type', content_type + '; charset=utf-8')
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('X-Content-Type-Options','nosniff')
        self.end_headers()
        self.wfile.write(payload)

    def mutate(self, method):
        if not self.trusted(): return self.reply(403, {'error':'禁止访问'})
        path = urlparse(self.path).path
        if path == '/api/session' and method == 'POST':
            try:
                obj = self.body()
                token = obj.get('token') if isinstance(obj, dict) else None
                if not isinstance(token, str) or not token.isascii() or not secrets.compare_digest(token, ACCESS_CODE):
                    return self.reply(401, {'error':'访问码不正确'})
                return self.reply(200, {'ok':True}, 'certdesk_session=' + SESSION_TOKEN + '; HttpOnly; SameSite=Strict; Path=/')
            except ValueError as exc:
                return self.reply(400, {'error':str(exc)})
        if not self.authenticated(): return self.reply(401, {'error':'请先输入本次启动的访问码'})
        if path == '/api/session' and method == 'DELETE':
            return self.reply(200, {'ok':True}, 'certdesk_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0')
        match = re.fullmatch(r'/api/certificates/(\d+)', path)
        try:
            if method == 'POST' and path == '/api/automation/check':
                return self.reply(200, automation.check_tls(self.body()))
            with connect() as db:
                if path == '/api/certificates' and method == 'POST':
                    obj = validate_certificate(self.body())
                    cur = db.execute('INSERT INTO certificates(name,domain,issuer,expires_on,owner,environment,location,notes) VALUES (?,?,?,?,?,?,?,?)', tuple(obj[f] for f in FIELDS))
                    db.commit()
                    return self.reply(201, cert(db.execute('SELECT * FROM certificates WHERE id=?',(cur.lastrowid,)).fetchone()))
                if match and method in ('PUT','DELETE'):
                    cid = int(match.group(1))
                    if not db.execute('SELECT 1 FROM certificates WHERE id=?',(cid,)).fetchone(): return self.reply(404, {'error':'证书不存在'})
                    if method == 'DELETE':
                        db.execute('DELETE FROM certificates WHERE id=?',(cid,))
                        db.commit()
                        return self.reply(200, {'ok':True})
                    obj = validate_certificate(self.body())
                    db.execute('UPDATE certificates SET name=?,domain=?,issuer=?,expires_on=?,owner=?,environment=?,location=?,notes=? WHERE id=?', (*[obj[f] for f in FIELDS],cid))
                    db.commit()
                    return self.reply(200, cert(db.execute('SELECT * FROM certificates WHERE id=?',(cid,)).fetchone()))
                if path == '/api/events' and method == 'POST':
                    obj = self.body()
                    if not isinstance(obj, dict) or set(obj) - {'certificate_id','event_type','notes'}: raise ValueError('无效的事件字段')
                    cid = obj.get('certificate_id')
                    if isinstance(cid, bool) or not isinstance(cid,int) or cid < 1: raise ValueError('无效的证书 ID')
                    if not db.execute('SELECT 1 FROM certificates WHERE id=?',(cid,)).fetchone(): return self.reply(404, {'error':'证书不存在'})
                    event_type = validate_text(obj.get('event_type',''),'event_type',True,80)
                    notes = validate_text(obj.get('notes',''),'notes',True,2000)
                    cur = db.execute('INSERT INTO events(certificate_id,event_type,notes,created_at) VALUES (?,?,?,?)', (cid,event_type,notes,datetime.now(timezone.utc).isoformat(timespec='seconds')))
                    db.commit()
                    row = db.execute('SELECT e.*,c.name AS certificate_name FROM events e JOIN certificates c ON c.id=e.certificate_id WHERE e.id=?',(cur.lastrowid,)).fetchone()
                    return self.reply(201, dict(row))
            return self.reply(404, {'error':'未找到'})
        except ValueError as exc:
            return self.reply(400, {'error':str(exc)})
        except sqlite3.Error:
            return self.reply(500, {'error':'数据库操作失败'})

    def do_POST(self): self.mutate('POST')
    def do_PUT(self): self.mutate('PUT')
    def do_DELETE(self): self.mutate('DELETE')

if __name__ == '__main__':
    init_db()
    print('证书管理台：http://127.0.0.1:8765', flush=True)
    print('本次启动访问码：' + ACCESS_CODE, flush=True)
    try:
        ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
    except KeyboardInterrupt:
        print('\n已停止')
