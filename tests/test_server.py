"""Server tests: run with  pytest -q server/tests  (SQLite)  or with DATABASE_URL=postgresql+psycopg://... (PostgreSQL)."""
import copy, gzip, io, json
from fastapi.testclient import TestClient
from sqlalchemy import update, select
from cat_server.main import app
from cat_server import store as st

ADMIN = 'example.admin@sample.cat.test'; VIEW = 'example.viewer@sample.cat.test'; CM = 'example.commercial.manager@sample.cat.test'
QS = 'example.quantity.surveyor@sample.cat.test'; SUB = 'example.subcontractor.user@sample.cat.test'; BADM = 'example.b.admin@sample.cat.test'; SUPER = 'admin@sample.cat.test'


def state(c): return c.get('/api/state').json()
def find(s, coll, pred): return next(r for r in s['records'][coll] if pred(r))
def sync(c, *ops): return c.post('/api/sync', json={'ops': list(ops)}).json()
def up(s, coll, rec): return {'coll': coll, 'id': rec['id'], 'op': 'upsert', 'data': rec, 'base': s['versions'][coll].get(rec['id'])}


def test_requires_sign_in():
    c = TestClient(app)
    assert c.get('/api/state').status_code == 401
    assert c.post('/api/sync', json={'ops': []}).status_code == 401
    assert c.get('/api/health').json()['ok'] is True


def test_wrong_password_and_lockout():
    c = TestClient(app)
    for i in range(5):
        assert c.post('/api/auth/login', json={'email': 'example.reviewer@sample.cat.test', 'password': 'nope-%d' % i}).status_code == 401
    r = c.post('/api/auth/login', json={'email': 'example.reviewer@sample.cat.test', 'password': 'Sample-2026-demo'})
    assert r.status_code == 423  # locked even with the right password
    with st.engine.begin() as con:
        n = con.execute(select(st.audit_log.c.aid).where(st.audit_log.c.action == 'Sign-in failed', st.audit_log.c.user_name == 'example.reviewer@sample.cat.test')).all()
        assert len(n) == 5  # every failure is in the audit trail
    with st.engine.begin() as con:
        con.execute(update(st.users_auth).where(st.users_auth.c.email == 'example.reviewer@sample.cat.test').values(failed=0, locked_until=None))


def test_cross_site_header_required(login):
    c = login(ADMIN); del c.headers['x-cat-request']
    assert c.post('/api/sync', json={'ops': []}).status_code == 403


def test_company_isolation(login):
    a = state(login(ADMIN)); b = state(login(BADM))
    assert {x['name'] for x in b['records']['companies']} == {'Example Specialist Contractor LLC'}
    a_ids = {r['id'] for coll in a['records'] for r in a['records'][coll] if coll != 'audit'}
    b_ids = {r['id'] for coll in b['records'] for r in b['records'][coll] if coll != 'audit'}
    assert not (a_ids & b_ids - {r['id'] for r in a['records']['users'] if r.get('role') == 'Super Administrator'})
    assert all(x['companyId'] == b['me']['companyId'] for x in b['records']['audit'] if x['companyId'])


def test_cannot_write_into_other_company(login):
    a = state(login(ADMIN)); bc = login(BADM)
    proj = copy.deepcopy(a['records']['projects'][0]); proj['name'] = 'hijack'
    r = sync(bc, {'coll': 'projects', 'id': proj['id'], 'op': 'upsert', 'data': proj, 'base': a['versions']['projects'][proj['id']]})
    assert r['rejected'] and r['rejected'][0]['reason'] == 'denied'
    new = {'id': 'pro_evil', 'companyId': a['me']['companyId'], 'number': 'X', 'name': 'planted'}
    r = sync(bc, {'coll': 'projects', 'id': 'pro_evil', 'op': 'upsert', 'data': new, 'base': None})
    assert r['rejected'][0]['message'] == 'Record belongs to another company'


def test_read_only_and_role_limits(login):
    v = login(VIEW); s = state(v)
    p = copy.deepcopy(s['records']['projects'][0]); p['name'] = 'x'
    assert sync(v, up(s, 'projects', p))['rejected'][0]['message'].endswith('is read-only')
    su = login(SUB); s2 = state(su)
    p2 = copy.deepcopy(s2['records']['projects'][0]); p2['name'] = 'y'
    assert 'cannot change projects' in sync(su, up(s2, 'projects', p2))['rejected'][0]['message']


def test_certification_restricted(login):
    q = login(QS); s = state(q)
    pay = copy.deepcopy(find(s, 'payments', lambda r: r['status'] == 'Under assessment')); pay['status'] = 'Certified'
    r = sync(q, up(s, 'payments', pay))
    assert 'certify' in r['rejected'][0]['message']
    cm = login(CM); s = state(cm); pay = copy.deepcopy(find(s, 'payments', lambda r: r['id'] == pay['id'])); pay['status'] = 'Certified'
    assert sync(cm, up(s, 'payments', pay))['applied']


def test_user_admin_rules(login):
    a = login(ADMIN); s = state(a)
    me = copy.deepcopy(find(s, 'users', lambda u: u['id'] == s['me']['id'])); me['role'] = 'Super Administrator'
    assert 'Super Administrator' in sync(a, up(s, 'users', me))['rejected'][0]['message']
    new = {'id': 'usr_newqs', 'name': 'New QS', 'email': 'new.qs@sample.cat.test', 'role': 'Quantity Surveyor', 'companyId': s['me']['companyId'], 'active': 'Active'}
    assert sync(a, {'coll': 'users', 'id': new['id'], 'op': 'upsert', 'data': new, 'base': None})['applied']
    assert a.post('/api/users/usr_newqs/password', json={'new': 'short'}).status_code == 400
    assert a.post('/api/users/usr_newqs/password', json={'new': 'Temporary-2026'}).status_code == 200
    n = TestClient(app); r = n.post('/api/auth/login', json={'email': 'new.qs@sample.cat.test', 'password': 'Temporary-2026'})
    assert r.status_code == 200 and r.json()['mustChange'] is True
    n.headers.update({'x-cat-request': '1'})
    assert n.post('/api/auth/password', json={'current': 'Temporary-2026', 'new': 'MyOwn-Password-9'}).status_code == 200
    b = login(BADM); assert b.post('/api/users/usr_newqs/password', json={'new': 'Hijacked-2026x'}).status_code == 403
    assert any(x['action'] == 'Access denied' and 'usr_newqs' in x['detail'] for x in state(b)['records']['audit'])
    # suspending ends sessions
    s = state(a); u = copy.deepcopy(find(s, 'users', lambda x: x['id'] == 'usr_newqs')); u['active'] = 'Suspended'
    assert sync(a, up(s, 'users', u))['applied']
    assert n.get('/api/state').status_code in (401, 403)


def test_optimistic_conflict_and_history(login):
    a = login(ADMIN); c = login(CM); sa = state(a); sc = state(c)
    v1 = copy.deepcopy(find(sa, 'variations', lambda r: r['ref'] == 'VO-002')); v1['assessed'] = 80000
    v2 = copy.deepcopy(find(sc, 'variations', lambda r: r['ref'] == 'VO-002')); v2['assessed'] = 99999
    assert sync(a, up(sa, 'variations', v1))['applied']
    r = sync(c, up(sc, 'variations', v2))
    assert r['rejected'][0]['reason'] == 'conflict' and r['rejected'][0]['current']['assessed'] == 80000
    h = a.get('/api/history/variations/' + v1['id']).json()
    assert [x['version'] for x in h][-2:] == [1, 2] and h[-1]['by'] == 'Example Admin' and h[-1]['data']['assessed'] == 80000


def test_changes_feed(login):
    a = login(ADMIN); v = login(VIEW); s0 = state(v)
    sa = state(a); r = copy.deepcopy(sa['records']['risks'][0]); r['owner'] = 'Changed owner'
    sync(a, up(sa, 'risks', r))
    ch = v.get('/api/changes?since=%d' % s0['seq']).json()['changes']
    assert any(x['id'] == r['id'] and x['data']['owner'] == 'Changed owner' for x in ch)
    assert not login(BADM).get('/api/changes?since=%d' % s0['seq']).json()['changes']


def test_delete_is_tombstoned_and_restorable_from_history(login):
    a = login(ADMIN); s = state(a); o = s['records']['opportunities'][0]
    assert sync(a, {'coll': 'opportunities', 'id': o['id'], 'op': 'delete', 'base': s['versions']['opportunities'][o['id']]})['applied']
    assert not any(x['id'] == o['id'] for x in state(a)['records']['opportunities'])
    h = a.get('/api/history/opportunities/' + o['id']).json(); assert h[-1]['action'] == 'Removed' and h[-1]['data']['ref'] == o['ref']


def test_audit_is_stamped_and_tamper_evident(login):
    v = login(VIEW)
    sync(v, {'coll': 'audit', 'id': 'au_x', 'op': 'upsert', 'data': {'id': 'au_x', 'user': 'Someone Else', 'role': 'Super Administrator', 'action': 'Viewed', 'entity': 'x', 'companyId': None}, 'base': None})
    a = login(ADMIN); rows = state(a)['records']['audit']
    mine = next(x for x in rows if x['action'] == 'Viewed')
    assert mine['user'] == 'Example Viewer' and mine['role'] == 'Read-only User'
    assert a.get('/api/audit/verify').json()['broken'] == []
    with st.engine.begin() as con:
        aid = con.execute(select(st.audit_log.c.aid).where(st.audit_log.c.action == 'Viewed')).scalar()
        con.execute(update(st.audit_log).where(st.audit_log.c.aid == aid).values(detail='tampered'))
    assert a.get('/api/audit/verify').json()['broken'] == [aid]
    with st.engine.begin() as con:
        con.execute(update(st.audit_log).where(st.audit_log.c.aid == aid).values(detail=''))
    assert a.get('/api/audit/verify').json()['broken'] == []


def test_server_kpis(login):
    k = login(ADMIN).get('/api/analytics/kpis').json()
    assert k['k03'] == 5 and k['k04'] == 7700000 and k['excluded'] == ['Imported pump sets (supply)']
    assert k['k05'] == k['k04'] + k['k10']
    assert round(k['certified'] - k['paid'], 2) == k['k13']
    kb = login(BADM).get('/api/analytics/kpis').json(); assert kb['k03'] == 0


def test_settings_scope(login):
    a = login(ADMIN); s = state(a); cid = s['me']['companyId']
    data = dict(s['settings'], aiRateLimit=999, allowAI={cid: True, 'other-company': True})
    assert sync(a, {'coll': '_settings', 'id': 'settings', 'op': 'upsert', 'data': data, 'base': s['settingsVersion']})['applied']
    s2 = state(a)['settings']
    assert s2['allowAI'] == {cid: True} and s2.get('aiRateLimit') != 999
    v = login(VIEW); sv = state(v)
    assert sync(v, {'coll': '_settings', 'id': 'settings', 'op': 'upsert', 'data': {}, 'base': sv['settingsVersion']})['rejected']


def test_ai_relay(login, ai_calls):
    b = login(BADM)
    assert b.post('/api/ai', json={'system': 's', 'content': 'hi'}).status_code == 403  # company not authorised
    a = login(ADMIN)  # authorised by test_settings_scope
    r = a.post('/api/ai', json={'system': 'sys', 'content': 'Contact jane@example.com or +971 50 123 4567 about clause 6.1', 'max_tokens': 50})
    assert r.status_code == 200 and 'Stub answer' in r.json()['text']
    sent = ai_calls[-1]['body']['messages'][0]['content']
    assert 'jane@example.com' not in sent and '[REDACTED-EMAIL]' in sent and '[REDACTED-PHONE]' in sent
    assert ai_calls[-1]['headers']['x-api-key'] == 'test-key'


def test_files(login):
    a = login(ADMIN); s = state(a); d = s['records']['docs'][0]
    assert a.post('/api/files/' + d['id'], files={'file': ('fake.pdf', b'not a pdf at all', 'application/pdf')}).status_code == 415
    pdf = b'%PDF-1.4\n' + b'x' * 2000
    assert a.post('/api/files/' + d['id'], files={'file': ('orig.pdf', pdf, 'application/pdf')}).status_code == 200
    g = a.get('/api/files/' + d['id']); assert g.status_code == 200 and g.content == pdf
    assert login(BADM).get('/api/files/' + d['id']).status_code == 404
    assert login(VIEW).post('/api/files/' + d['id'], files={'file': ('o.pdf', pdf, 'application/pdf')}).status_code == 403


def test_scheduled_email(login, mails):
    a = login(ADMIN)
    assert a.post('/api/schedules', json={'name': 'Weekly', 'recipients': 'not-an-email'}).status_code == 400
    sid = a.post('/api/schedules', json={'name': 'Weekly summary', 'recipients': 'cm@example.com, pm@example.com', 'frequency': 'weekly', 'hour': 4, 'weekday': 0}).json()['id']
    r = a.post('/api/schedules/%s/run' % sid).json()
    assert r['status'].startswith('Sent to 2'), r
    m = mails[-1]; assert set(m['to']) == {'cm@example.com', 'pm@example.com'} and '7,700,000.00' in m['data']
    assert login(VIEW).post('/api/schedules', json={'name': 'x', 'recipients': 'a@b.c'}).status_code == 403
    assert login(BADM).post('/api/schedules/%s/run' % sid).status_code == 404


def test_due_logic():
    import datetime as dt
    from types import SimpleNamespace as N
    from cat_server.jobs import due
    t = dt.datetime(2026, 10, 19, 4, 0, tzinfo=dt.timezone.utc)  # a Monday
    assert due(N(active=True, last_run=None, hour=4, frequency='weekly', weekday=0, monthday=1), t)
    assert not due(N(active=True, last_run=t, hour=4, frequency='weekly', weekday=0, monthday=1), t)
    assert not due(N(active=True, last_run=None, hour=4, frequency='weekly', weekday=2, monthday=1), t)
    assert due(N(active=True, last_run=None, hour=4, frequency='daily', weekday=0, monthday=1), t)


def test_backup_and_restore_roundtrip(login):
    sup = login(SUPER); assert login(ADMIN).get('/api/admin/backup').status_code == 403
    blob = sup.get('/api/admin/backup').content
    before = state(sup)
    s = state(sup); p = copy.deepcopy(s['records']['projects'][0]); p['name'] = 'Changed after backup'
    assert sync(sup, up(s, 'projects', p))['applied']
    r = sup.post('/api/admin/restore', files={'file': ('b.json.gz', blob, 'application/gzip')})
    assert r.status_code == 200 and r.json()['audit']['broken'] == []
    sup2 = login(SUPER)
    after = state(sup2)
    assert {x['id']: x['name'] for x in after['records']['projects']} == {x['id']: x['name'] for x in before['records']['projects']}
    assert sup2.post('/api/admin/backup/now').json()['rows'] > 100
