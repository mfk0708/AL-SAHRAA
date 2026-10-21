"""HTTP API for Contract Assessment Tools.  Run with:  uvicorn cat_server.main:app"""
import base64, hashlib, hmac, json, os, secrets, time, datetime as dt
from pathlib import Path
from typing import Any, Optional
import httpx
from fastapi import FastAPI, Request, Response, HTTPException, Depends, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from pydantic import BaseModel
from sqlalchemy import select, insert, update, delete, func, and_
from . import config, store as st, logic as L
from fastapi.middleware.cors import CORSMiddleware



app = FastAPI(title='Contract Assessment Tools API', version=config.APP_VERSION, docs_url='/api/docs', openapi_url='/api/openapi.json')
st.init_db()
COOKIE = 'cat_session'
now = st.now

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------- passwords & sessions ----------------
def hash_pw(pw: str) -> str:
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return 'scrypt$' + base64.b64encode(salt).decode() + '$' + base64.b64encode(h).decode()


def check_pw(pw: str, stored: Optional[str]) -> bool:
    if not stored or not stored.startswith('scrypt$'):
        return False
    _, s, h = stored.split('$')
    calc = hashlib.scrypt(pw.encode(), salt=base64.b64decode(s), n=2 ** 14, r=8, p=1, dklen=32)
    return hmac.compare_digest(calc, base64.b64decode(h))


def pw_policy(pw: str):
    if len(pw) < 10 or not any(c.isalpha() for c in pw) or not any(c.isdigit() for c in pw):
        raise HTTPException(400, 'Passwords need at least 10 characters including letters and digits.')


def ip_of(req: Request):
    return (req.headers.get('x-forwarded-for') or (req.client.host if req.client else '') or '').split(',')[0].strip()


def load_user(c, uid):
    r = st.get_record(c, 'users', uid)
    if not r or r.removed:
        return None
    return dict(r.data, companyId=r.data.get('companyId'))


def current_user(req: Request):
    tok = req.cookies.get(COOKIE)
    if not tok:
        raise HTTPException(401, 'Not signed in')
    th = hashlib.sha256(tok.encode()).hexdigest()
    with st.engine.begin() as c:
        s = c.execute(select(st.sessions).where(st.sessions.c.token_hash == th)).first()
        t = now()
        exp = s.expires if s and s.expires and s.expires.tzinfo else (s.expires.replace(tzinfo=dt.timezone.utc) if s and s.expires else None)
        if not s or exp < t:
            raise HTTPException(401, 'Session expired – please sign in again')
        u = load_user(c, s.user_id)
        if not u or not L.active(u):
            raise HTTPException(403, 'User is suspended or no longer exists')
        c.execute(update(st.sessions).where(st.sessions.c.token_hash == th).values(last_seen=t, expires=t + dt.timedelta(hours=config.SESSION_HOURS)))
    if req.method not in ('GET', 'HEAD') and req.headers.get('x-cat-request') != '1':
        raise HTTPException(403, 'Missing request header (cross-site request refused)')
    return u


# ---------------- middleware ----------------
@app.middleware('http')
async def headers_and_metrics(request: Request, call_next):
    t0 = time.perf_counter()
    resp = await call_next(request)
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['Referrer-Policy'] = 'same-origin'
    if request.url.path == '/' or request.url.path.endswith('.html'):
        # everything the page needs is served by this server: no external hosts are allowed
        resp.headers['Content-Security-Policy'] = ("default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' blob:; worker-src 'self' blob:; "
                                                   "style-src 'self' 'unsafe-inline'; font-src 'self' data:; img-src 'self' data: blob:; "
                                                   "connect-src 'self' blob: data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
        resp.headers['Cache-Control'] = 'no-store'
    p = request.url.path
    if p.startswith('/vendor/') and resp.status_code == 200:
        resp.headers['Cache-Control'] = 'public, max-age=604800'
    if p.startswith('/api/') and p != '/api/health':
        try:
            with st.engine.begin() as c:
                c.execute(insert(st.req_metrics).values(path=p[:200], status=resp.status_code, ms=round((time.perf_counter() - t0) * 1000, 1)))
        except Exception:
            pass
    return resp


# ---------------- web app ----------------
@app.get('/', response_class=HTMLResponse)
def index():
    if not config.WEB_INDEX.exists():
        return HTMLResponse('<h1>Web build missing</h1><p>Place index.html in server/web/.</p>', 500)
    html = config.WEB_INDEX.read_text(encoding='utf-8')
    cfg = json.dumps({'api': '/api', 'version': config.APP_VERSION, 'db': st.engine.dialect.name})
    return HTMLResponse(html.replace('<title>', '<script>window.CAT_SERVER=' + cfg + ';</script><title>', 1))
@app.get('/config.js')
def frontend_config():
    return FileResponse(
        config.WEB_INDEX.parent / 'config.js',
        media_type='application/javascript'
    )

@app.get('/api/health')
def health():
    with st.engine.connect() as c:
        c.execute(select(func.count()).select_from(st.schema_meta)).scalar()
    return {'ok': True, 'version': config.APP_VERSION, 'db': st.engine.dialect.name, 'schema': st.SCHEMA_VERSION,
            'ai': bool(config.ANTHROPIC_API_KEY), 'smtp': bool(config.SMTP_HOST), 'time': now().isoformat()}


# ---------------- auth ----------------
class Login(BaseModel):
    email: str
    password: str


@app.post('/api/auth/login')
def login(body: Login, request: Request, response: Response):
    email = body.email.strip().lower()
    err = None
    with st.engine.begin() as c:  # failures are committed before the error is raised (so lockout counts persist)
        a = c.execute(select(st.users_auth).where(func.lower(st.users_auth.c.email) == email)).first()
        t = now()
        u = load_user(c, a.user_id) if a else None
        if a and a.locked_until and (a.locked_until if a.locked_until.tzinfo else a.locked_until.replace(tzinfo=dt.timezone.utc)) > t:
            st.write_audit(c, (u or {}).get('companyId'), {'name': email}, 'Sign-in refused (locked)', 'auth', '', ip_of(request))
            err = (423, 'Account temporarily locked after repeated failed sign-ins. Try again in 15 minutes.')
        elif not a or not u or not check_pw(body.password, a.pw_hash):
            if a:
                f = (a.failed or 0) + 1
                c.execute(update(st.users_auth).where(st.users_auth.c.user_id == a.user_id).values(
                    failed=f, locked_until=(t + dt.timedelta(minutes=15)) if f >= 5 else None))
            st.write_audit(c, (u or {}).get('companyId'), {'name': email}, 'Sign-in failed', 'auth', '', ip_of(request))
            err = (401, 'Email or password is incorrect.')
        elif not L.active(u):
            err = (403, 'This user is suspended.')
    if err:
        raise HTTPException(*err)
    with st.engine.begin() as c:
        tok = secrets.token_urlsafe(32)
        c.execute(insert(st.sessions).values(token_hash=hashlib.sha256(tok.encode()).hexdigest(), user_id=u['id'], created=t, last_seen=t,
                                             expires=t + dt.timedelta(hours=config.SESSION_HOURS), ip=ip_of(request), ua=request.headers.get('user-agent', '')[:300]))
        c.execute(update(st.users_auth).where(st.users_auth.c.user_id == u['id']).values(failed=0, locked_until=None, last_login=t))
        st.write_audit(c, u.get('companyId'), u, 'Signed in', 'auth', '', ip_of(request))
    response.set_cookie(COOKIE, tok, httponly=True, samesite='strict', secure=config.COOKIE_SECURE, max_age=int(config.SESSION_HOURS * 3600), path='/')
    return {'ok': True, 'user': L.clean(u), 'mustChange': bool(a.must_change)}


@app.post('/api/auth/logout')
def logout(request: Request, response: Response, u=Depends(current_user)):
    tok = request.cookies.get(COOKIE, '')
    with st.engine.begin() as c:
        c.execute(delete(st.sessions).where(st.sessions.c.token_hash == hashlib.sha256(tok.encode()).hexdigest()))
        st.write_audit(c, u.get('companyId'), u, 'Signed out', 'auth', '', ip_of(request))
    response.delete_cookie(COOKIE, path='/')
    return {'ok': True}


class PwChange(BaseModel):
    current: Optional[str] = None
    new: str


@app.post('/api/auth/password')
def change_password(body: PwChange, request: Request, u=Depends(current_user)):
    pw_policy(body.new)
    with st.engine.begin() as c:
        a = c.execute(select(st.users_auth).where(st.users_auth.c.user_id == u['id'])).first()
        if not a or not check_pw(body.current or '', a.pw_hash):
            raise HTTPException(400, 'Current password is incorrect.')
        c.execute(update(st.users_auth).where(st.users_auth.c.user_id == u['id']).values(pw_hash=hash_pw(body.new), must_change=False))
        st.write_audit(c, u.get('companyId'), u, 'Changed own password', 'auth', '', ip_of(request))
    return {'ok': True}


@app.post('/api/users/{uid}/password')
def set_password(uid: str, body: PwChange, request: Request, u=Depends(current_user)):
    pw_policy(body.new)
    with st.engine.begin() as c:
        t = load_user(c, uid)
        if not t:
            raise HTTPException(404, 'User not found')
        if not L.role_of(u).get('users') or (not L.is_super(u) and t.get('companyId') != u.get('companyId')) or (t.get('role') == 'Super Administrator' and not L.is_super(u)):
            denied = True
        else:
            denied = False
    if denied:
        with st.engine.begin() as c:
            st.write_audit(c, u.get('companyId'), u, 'Access denied', 'users', 'attempted to set a password for user ' + uid, ip_of(request))
        raise HTTPException(403, 'Your role cannot set this user’s password.')
    with st.engine.begin() as c:
        email = (t.get('email') or '').strip().lower()
        if not email:
            raise HTTPException(400, 'Give the user an e-mail address first; it is their sign-in name.')
        a = c.execute(select(st.users_auth).where(st.users_auth.c.user_id == uid)).first()
        if a:
            c.execute(update(st.users_auth).where(st.users_auth.c.user_id == uid).values(pw_hash=hash_pw(body.new), must_change=True, failed=0, locked_until=None))
        else:
            c.execute(insert(st.users_auth).values(user_id=uid, email=email, pw_hash=hash_pw(body.new), must_change=True))
        c.execute(delete(st.sessions).where(st.sessions.c.user_id == uid))
        st.write_audit(c, t.get('companyId'), u, 'Set password', 'users', t.get('name', ''), ip_of(request))
    return {'ok': True}


@app.get('/api/me')
def me(u=Depends(current_user)):
    return L.clean(u)


# ---------------- state & sync ----------------
def _ws_get(c, key, default):
    r = c.execute(select(st.workspace).where(st.workspace.c.key == key)).first()
    return (r.data if r else default), (r.version if r else 0)


def _company_ctx(c, u):
    """Return (rows by coll, pk->project map, allowed project set) for what this user can see."""
    q = select(st.records).where(st.records.c.removed == False)  # noqa: E712
    if not L.is_super(u):
        q = q.where((st.records.c.company_id == u.get('companyId')) | (st.records.c.coll == 'companies'))
    rows = list(c.execute(q))
    pk_project = {r.id: r.data.get('projectId') for r in rows if r.coll == 'packages'}
    allowed = None
    if not L.is_super(u):
        allowed = L.allowed_projects(u, [r.data for r in rows if r.coll == 'projects' and r.company_id == u.get('companyId')])
    return rows, pk_project, allowed


AUDIT_KEEP = 2000


def _audit_rows(c, u):
    q = select(st.audit_log).order_by(st.audit_log.c.aid.desc()).limit(AUDIT_KEEP)
    if not L.is_super(u):
        q = q.where(st.audit_log.c.company_id == u.get('companyId'))
    return [{'id': 'srv-%d' % r.aid, 'at': (r.at if r.at.tzinfo else r.at.replace(tzinfo=dt.timezone.utc)).isoformat(), 'companyId': r.company_id,
             'user': r.user_name, 'role': r.role, 'action': r.action, 'entity': r.entity, 'detail': r.detail} for r in c.execute(q)]


@app.get('/api/state')
def state(u=Depends(current_user)):
    with st.engine.begin() as c:
        rows, pk_project, allowed = _company_ctx(c, u)
        out = {k: [] for k in L.COLLS}; vers = {k: {} for k in L.COLLS}
        for r in rows:
            if r.coll == 'audit' or not L.visible(u, r.coll, r.data, r.company_id, pk_project, allowed):
                continue
            out[r.coll].append(L.clean(r.data)); vers[r.coll][r.id] = r.version
        out['audit'] = _audit_rows(c, u)
        seq = c.execute(select(st.counters.c.v).where(st.counters.c.name == 'seq')).scalar_one()
        settings, sv = _ws_get(c, 'settings', {})
        runs, rv = _ws_get(c, 'testRuns', [])
        prefs, pv = _ws_get(c, 'prefs:' + u['id'], {})
        a = c.execute(select(st.users_auth.c.must_change).where(st.users_auth.c.user_id == u['id'])).scalar()
    return {'me': L.clean(u), 'records': out, 'versions': vers, 'seq': seq, 'settings': L.clean(settings), 'settingsVersion': sv,
            'testRuns': runs, 'prefs': prefs, 'mustChange': bool(a),
            'server': {'version': config.APP_VERSION, 'db': st.engine.dialect.name, 'ai': bool(config.ANTHROPIC_API_KEY), 'smtp': bool(config.SMTP_HOST)}}


class Op(BaseModel):
    coll: str
    id: str
    op: str
    data: Optional[dict] = None
    base: Optional[int] = None


class SyncBody(BaseModel):
    ops: list[Op]


def _company_of(coll, data):
    if coll == 'companies':
        return data.get('id')
    return data.get('companyId')


@app.post('/api/sync')
def sync(body: SyncBody, request: Request, u=Depends(current_user)):
    applied, rejected = [], []
    for op in body.ops[:2000]:
        try:
            with st.engine.begin() as c:
                if op.coll == '_settings':
                    if not L.role_of(u).get('admin'):
                        raise L.Denied('Only administrators can change workspace settings')
                    cur, v = _ws_get(c, 'settings', {})
                    if op.base is not None and op.base != v:
                        raise L.Denied('conflict')
                    data = L.clean(op.data or {})
                    if not L.is_super(u):  # company admins may only change their own company's AI authorisation
                        allow = dict(cur.get('allowAI') or {}); allow[u.get('companyId')] = bool((data.get('allowAI') or {}).get(u.get('companyId')))
                        data = dict(cur, **{k: v2 for k, v2 in data.items() if k in ('workflows', 'holidays', 'ocr')}, allowAI=allow)
                    _ws_put(c, 'settings', data, v, u)
                    st.write_audit(c, u.get('companyId'), u, 'Updated', 'workspace settings', '', ip_of(request))
                    applied.append({'coll': op.coll, 'id': op.id, 'version': v + 1, 'current': L.clean(data)}); continue
                if op.coll == '_testRuns' and not L.role_of(u).get('admin'):
                    raise L.Denied('Only administrators can record test runs')
                if op.coll in ('_testRuns', '_prefs'):
                    key = 'testRuns' if op.coll == '_testRuns' else 'prefs:' + u['id']
                    cur, v = _ws_get(c, key, None)
                    _ws_put(c, key, op.data if op.coll == '_prefs' else (op.data or {}).get('runs', [])[:30], v, u)
                    applied.append({'coll': op.coll, 'id': op.id, 'version': v + 1}); continue
                if op.coll == 'audit':
                    d = op.data or {}
                    L.can_write(u, 'audit', d.get('companyId'), None, d)
                    st.write_audit(c, d.get('companyId') if L.is_super(u) else u.get('companyId'), u, d.get('action', ''), d.get('entity', ''), d.get('detail', ''), ip_of(request))
                    applied.append({'coll': 'audit', 'id': op.id, 'version': 1}); continue
                ex = st.get_record(c, op.coll, op.id)
                old = ex.data if ex is not None and not ex.removed else None
                if op.base is not None and ex is not None and ex.version != op.base:
                    rejected.append({'coll': op.coll, 'id': op.id, 'reason': 'conflict', 'message': 'Changed by %s since you loaded it' % (ex.updated_by or 'another user'),
                                     'current': None if ex.removed else L.clean(ex.data), 'version': ex.version}); continue
                if op.base is None and old is not None:
                    rejected.append({'coll': op.coll, 'id': op.id, 'reason': 'conflict', 'message': 'A record with this id already exists',
                                     'current': L.clean(old), 'version': ex.version}); continue
                if op.op == 'delete':
                    if old is None:
                        applied.append({'coll': op.coll, 'id': op.id, 'version': ex.version if ex else 0}); continue
                    L.can_write(u, op.coll, ex.company_id, old, None)
                    ver, seq = st.put_record(c, op.coll, op.id, ex.company_id, old, u, 'Removed', ex)
                    if op.coll == 'users':
                        c.execute(delete(st.users_auth).where(st.users_auth.c.user_id == op.id)); c.execute(delete(st.sessions).where(st.sessions.c.user_id == op.id))
                    applied.append({'coll': op.coll, 'id': op.id, 'version': ver, 'seq': seq}); continue
                data = L.clean(op.data or {})
                if data.get('id') != op.id:
                    raise L.Denied('Record id mismatch')
                comp = _company_of(op.coll, data)
                if op.coll not in L.GLOBAL_COLLS and not comp:
                    raise L.Denied('Record has no company')
                if ex is not None and ex.company_id != comp and op.coll not in ('users',):
                    raise L.Denied('A record cannot be moved to another company')
                L.can_write(u, op.coll, comp, old, data)
                if op.coll == 'users':
                    _sync_user_auth(c, data)
                ver, seq = st.put_record(c, op.coll, op.id, comp, data, u, 'Created' if old is None else 'Updated', ex)
                applied.append({'coll': op.coll, 'id': op.id, 'version': ver, 'seq': seq})
        except L.Denied as e:
            msg = str(e)
            if msg == 'conflict':
                with st.engine.begin() as c:
                    cur, v = _ws_get(c, 'settings', {})
                rejected.append({'coll': op.coll, 'id': op.id, 'reason': 'conflict', 'message': 'Settings changed by another administrator', 'current': L.clean(cur), 'version': v})
                continue
            with st.engine.begin() as c:
                st.write_audit(c, u.get('companyId'), u, 'Access denied', op.coll, msg + ' (' + op.op + ' ' + op.id + ')', ip_of(request))
                ex = st.get_record(c, op.coll, op.id) if not op.coll.startswith('_') else None
            rejected.append({'coll': op.coll, 'id': op.id, 'reason': 'denied', 'message': msg,
                             'current': None if (ex is None or ex.removed) else L.clean(ex.data), 'version': ex.version if ex else 0})
        except HTTPException:
            raise
        except Exception as e:  # validation / constraint problems
            rejected.append({'coll': op.coll, 'id': op.id, 'reason': 'error', 'message': str(e)[:300]})
    with st.engine.connect() as c:
        seq = c.execute(select(st.counters.c.v).where(st.counters.c.name == 'seq')).scalar_one()
    return {'applied': applied, 'rejected': rejected, 'seq': seq}


def _ws_put(c, key, data, v, u):
    if v:
        c.execute(update(st.workspace).where(st.workspace.c.key == key).values(data=data, version=v + 1, updated_at=now(), updated_by=u.get('name')))
    else:
        c.execute(insert(st.workspace).values(key=key, data=data, version=1, updated_at=now(), updated_by=u.get('name')))


def _sync_user_auth(c, data):
    email = (data.get('email') or '').strip().lower()
    a = c.execute(select(st.users_auth).where(st.users_auth.c.user_id == data['id'])).first()
    if email:
        clash = c.execute(select(st.users_auth.c.user_id).where(func.lower(st.users_auth.c.email) == email, st.users_auth.c.user_id != data['id'])).first()
        if clash:
            raise L.Denied('Another user already uses the e-mail ' + email)
        if a and a.email != email:
            c.execute(update(st.users_auth).where(st.users_auth.c.user_id == data['id']).values(email=email))
    if data.get('active') == 'Suspended':
        c.execute(delete(st.sessions).where(st.sessions.c.user_id == data['id']))


@app.get('/api/changes')
def changes(since: int, u=Depends(current_user)):
    with st.engine.begin() as c:
        q = select(st.records).where(st.records.c.seq > since).order_by(st.records.c.seq).limit(5000)
        if not L.is_super(u):
            q = q.where((st.records.c.company_id == u.get('companyId')) | (st.records.c.coll == 'companies'))
        rows = list(c.execute(q))
        _, pk_project, allowed = _company_ctx(c, u)
        seq = c.execute(select(st.counters.c.v).where(st.counters.c.name == 'seq')).scalar_one()
    out = [{'coll': r.coll, 'id': r.id, 'version': r.version, 'removed': r.removed, 'by': r.updated_by, 'data': None if r.removed else L.clean(r.data)}
           for r in rows if r.coll != 'audit' and L.visible(u, r.coll, r.data, r.company_id, pk_project, allowed)]
    return {'changes': out, 'seq': seq}


@app.get('/api/history/{coll}/{rid}')
def history(coll: str, rid: str, u=Depends(current_user)):
    with st.engine.begin() as c:
        ex = st.get_record(c, coll, rid)
        if not ex or (not L.is_super(u) and ex.company_id != u.get('companyId') and coll != 'companies'):
            raise HTTPException(404, 'Not found')
        rows = c.execute(select(st.record_history).where(st.record_history.c.coll == coll, st.record_history.c.id == rid).order_by(st.record_history.c.hid))
        return [{'version': r.version, 'action': r.action, 'by': r.user_name, 'at': r.at.isoformat(), 'data': L.clean(r.data)} for r in rows]


@app.get('/api/audit/verify')
def audit_verify(u=Depends(current_user)):
    if not L.role_of(u).get('admin'):
        raise HTTPException(403, 'Administrators only')
    with st.engine.begin() as c:
        return st.verify_audit_chain(c)


# ---------------- analytics (server-side aggregation) ----------------
def company_rows(c, company_id):
    rows = {}
    for r in c.execute(select(st.records).where(st.records.c.company_id == company_id, st.records.c.removed == False)):  # noqa: E712
        if r.data.get('deleted'):
            continue
        rows.setdefault(r.coll, []).append(r.data)
    comp = st.get_record(c, 'companies', company_id)
    return rows, (comp.data if comp else {})


@app.get('/api/analytics/kpis')
def analytics_kpis(companyId: Optional[str] = None, u=Depends(current_user)):
    cid = companyId if (companyId and L.is_super(u)) else u.get('companyId')
    if not cid:
        raise HTTPException(400, 'No company selected')
    t0 = time.perf_counter()
    with st.engine.begin() as c:
        rows, comp = company_rows(c, cid)
        _, _, allowed = _company_ctx(c, u)
    if allowed is not None:
        pk_project = {p['id']: p.get('projectId') for p in rows.get('packages', [])}
        rows = {k: [d for d in v if L.visible(u, k, d, cid, pk_project, allowed)] for k, v in rows.items()}
    out = L.kpis(rows, comp)
    out['ms'] = round((time.perf_counter() - t0) * 1000, 1)
    out['companyId'] = cid
    return out


# ---------------- files (original uploads) ----------------
@app.post('/api/files/{doc_id}')
async def upload(doc_id: str, request: Request, file: UploadFile = File(...), u=Depends(current_user)):
    with st.engine.begin() as c:
        d = st.get_record(c, 'docs', doc_id)
    if not d or d.removed or (not L.is_super(u) and d.company_id != u.get('companyId')):
        raise HTTPException(404, 'Document record not found – save the document first')
    if not L.role_of(u).get('edit'):
        raise HTTPException(403, 'Your role cannot upload documents')
    data = await file.read()
    if len(data) > config.MAX_UPLOAD_MB * 1024 * 1024:
        raise HTTPException(413, 'File exceeds %d MB' % config.MAX_UPLOAD_MB)
    sig = data[:8]
    ok = sig.startswith(b'%PDF') or sig.startswith(b'PK') or sig[:2] in (b'\xff\xd8', b'\x89P', b'II', b'MM') or file.filename.lower().endswith(('.txt', '.csv'))
    if not ok:
        raise HTTPException(415, 'File type not accepted (signature check failed)')
    sha = hashlib.sha256(data).hexdigest()
    folder = config.FILES_DIR / (d.company_id or 'none'); folder.mkdir(parents=True, exist_ok=True)
    path = folder / sha
    if not path.exists():
        path.write_bytes(data)
    with st.engine.begin() as c:
        c.execute(delete(st.files).where(st.files.c.doc_id == doc_id))
        c.execute(insert(st.files).values(doc_id=doc_id, company_id=d.company_id, name=file.filename[:300], type=file.content_type or '', size=len(data), sha256=sha, path=str(path), by=u.get('name')))
        st.write_audit(c, d.company_id, u, 'Uploaded original', 'docs', file.filename, ip_of(request))
    return {'ok': True, 'sha256': sha, 'size': len(data)}


@app.get('/api/files/{doc_id}')
def download(doc_id: str, u=Depends(current_user)):
    with st.engine.begin() as c:
        f = c.execute(select(st.files).where(st.files.c.doc_id == doc_id)).first()
    if not f or (not L.is_super(u) and f.company_id != u.get('companyId')):
        raise HTTPException(404, 'Original not stored on the server')
    p = Path(f.path)
    if not p.exists() or hashlib.sha256(p.read_bytes()).hexdigest() != f.sha256:
        raise HTTPException(500, 'Stored file failed its integrity check')
    return FileResponse(p, media_type=f.type or 'application/octet-stream', filename=f.name)


# ---------------- AI relay ----------------
class AIReq(BaseModel):
    system: str
    content: str
    max_tokens: int = 1500
    model: Optional[str] = None
    companyId: Optional[str] = None


@app.post('/api/ai')
def ai(body: AIReq, request: Request, u=Depends(current_user)):
    cid = body.companyId if (body.companyId and L.is_super(u)) else u.get('companyId')
    with st.engine.begin() as c:
        settings, _ = _ws_get(c, 'settings', {})
        if not (settings.get('allowAI') or {}).get(cid):
            raise HTTPException(403, 'External AI processing is not authorised for this company.')
        if not config.ANTHROPIC_API_KEY:
            raise HTTPException(503, 'The server has no Claude API key configured (ANTHROPIC_API_KEY).')
        t = now()
        recent = c.execute(select(func.count()).select_from(st.ai_usage).where(st.ai_usage.c.company_id == cid, st.ai_usage.c.at > t - dt.timedelta(minutes=1))).scalar()
        if recent >= int(settings.get('aiRateLimit') or 10):
            raise HTTPException(429, 'AI rate limit reached for this company. Try again shortly.')
        start = t.replace(hour=0, minute=0, second=0, microsecond=0)
        used = c.execute(select(func.coalesce(func.sum(st.ai_usage.c.tokens_in + st.ai_usage.c.tokens_out), 0)).where(st.ai_usage.c.company_id == cid, st.ai_usage.c.at >= start)).scalar()
        if used >= int(settings.get('aiDailyTokens') or 200000):
            raise HTTPException(429, 'Daily AI token budget for this company is used up.')
    content = L.redact(body.content) if settings.get('aiRedact', True) else body.content
    t0 = time.perf_counter()
    try:
        r = httpx.post(config.ANTHROPIC_BASE_URL.rstrip('/') + '/v1/messages', timeout=120,
                       headers={'x-api-key': config.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json'},
                       json={'model': body.model or settings.get('model') or 'claude-sonnet-5-5', 'max_tokens': min(body.max_tokens, 4000),
                             'system': body.system, 'messages': [{'role': 'user', 'content': content}]})
        j = r.json()
        if r.status_code != 200:
            raise RuntimeError('Claude API error %s: %s' % (r.status_code, (j.get('error') or {}).get('message', '')))
        text = '\n'.join(x.get('text', '') for x in j.get('content', []) if x.get('type') == 'text')
        us = j.get('usage') or {}
        with st.engine.begin() as c:
            c.execute(insert(st.ai_usage).values(company_id=cid, user_id=u['id'], tokens_in=us.get('input_tokens', 0), tokens_out=us.get('output_tokens', 0), ok=True, detail=body.model or ''))
            st.write_audit(c, cid, u, 'AI request', 'ai', '%s output tokens' % us.get('output_tokens', 0), ip_of(request))
        return {'text': text, 'usage': us, 'ms': round((time.perf_counter() - t0) * 1000)}
    except Exception as e:
        with st.engine.begin() as c:
            c.execute(insert(st.ai_usage).values(company_id=cid, user_id=u['id'], ok=False, detail=str(e)[:500]))
        raise HTTPException(502, str(e))


# front-end libraries, fonts and OCR data are served by this server (no internet access needed by browsers)
from fastapi.staticfiles import StaticFiles  # noqa: E402
_vendor = config.WEB_INDEX.parent / 'vendor'
if _vendor.is_dir():
    app.mount('/vendor', StaticFiles(directory=str(_vendor)), name='vendor')
from . import jobs  # noqa: E402  (schedules, e-mail, backups, monitoring routes)
jobs.register(app, current_user, ip_of, company_rows)


@app.get('/api/diagnostic-login')
def diagnostic_login():
    email = 'fahad@alsahraa.ae'

    database_path = st.engine.url.database
    database_file = Path(database_path) if database_path else None
    database_exists = database_file.exists() if database_file else False

    with st.engine.connect() as c:
        a = c.execute(
            select(
                st.users_auth.c.user_id,
                st.users_auth.c.email
            ).where(
                func.lower(st.users_auth.c.email) == email
            )
        ).first()

        user_exists = bool(a and load_user(c, a.user_id))

        return {
            'database': st.engine.dialect.name,
            'database_path': database_path,
            'database_file_exists': database_exists,
            'database_size': (
                database_file.stat().st_size
                if database_exists
                else None
            ),
            'account_exists': a is not None,
            'account_email': a.email if a else None,
            'account_user_id_exists': user_exists
        }
