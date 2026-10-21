"""Command line:  python -m cat_server.cli <command>

  init-db                                   create tables
  create-admin --email E --name N --password P   create a Super Administrator
  seed-sample [--password P]                 load the sample project (two example companies)
  set-password --email E --password P        reset a user's password
  backup                                     write a backup to CAT_BACKUP_DIR
  verify-audit                               check the audit-log hash chain
"""
import argparse, json, os, re, secrets, sys
from pathlib import Path
from .run import load_env
if __name__ == '__main__':
    os.environ['CAT_RUN_JOBS'] = '0'  # command-line use: no background scheduler
load_env(os.environ.get('CAT_ENV_FILE') or str(Path(__file__).resolve().parent.parent / 'cat.env'))  # same settings as the server
from sqlalchemy import select, insert, update, func
from . import config, store as st, logic as L
from .main import hash_pw

SAMPLE = Path(__file__).resolve().parent.parent / 'sample' / 'sample_state.json'
SYSTEM = {'id': 'system', 'name': 'Sample loader', 'role': 'Super Administrator'}


def slug(s):
    return re.sub(r'[^a-z0-9]+', '.', s.lower()).strip('.')


def seed_sample(password, path=SAMPLE):
    data = json.loads(Path(path).read_text())
    st.init_db()
    made = []
    with st.engine.begin() as c:
        if c.execute(select(func.count()).select_from(st.records).where(st.records.c.coll == 'companies')).scalar():
            raise SystemExit('The database already has companies; seed-sample only runs on an empty database.')
        for coll in L.COLLS:
            if coll == 'audit':
                continue
            for r in data.get(coll, []):
                r = L.clean(r)
                if coll == 'users':
                    if not r.get('email'):
                        r['email'] = slug(r['name']) + '@sample.cat.test'
                    r.setdefault('active', 'Active')
                comp = r['id'] if coll == 'companies' else r.get('companyId')
                st.put_record(c, coll, r['id'], comp, r, SYSTEM, 'Created')
                if coll == 'users':
                    c.execute(insert(st.users_auth).values(user_id=r['id'], email=r['email'].lower(), pw_hash=hash_pw(password), must_change=False))
                    made.append((r['name'], r['role'], r['email']))
        settings = L.clean(data.get('settings') or {})
        c.execute(insert(st.workspace).values(key='settings', data=settings, version=1, updated_by='Sample loader'))
        for a in reversed(data.get('audit', [])[:500]):
            st.write_audit(c, a.get('companyId'), {'name': a.get('user'), 'role': a.get('role')}, a.get('action'), a.get('entity'), a.get('detail'))
        st.write_audit(c, None, SYSTEM, 'Loaded sample project', 'system', '%d users' % len(made))
    return made


def main(argv=None):
    p = argparse.ArgumentParser(prog='cat_server.cli')
    p.add_argument('cmd', choices=['init-db', 'create-admin', 'seed-sample', 'set-password', 'backup', 'verify-audit'])
    p.add_argument('--email'); p.add_argument('--name', default='System Administrator'); p.add_argument('--password'); p.add_argument('--file')
    a = p.parse_args(argv)
    st.init_db()
    if a.cmd == 'init-db':
        print('Database ready:', st.engine.url.render_as_string(hide_password=True))
    elif a.cmd == 'create-admin':
        if not a.email or not a.password:
            raise SystemExit('--email and --password are required')
        uid = 'usr' + secrets.token_hex(6)
        u = {'id': uid, 'name': a.name, 'email': a.email.lower(), 'role': 'Super Administrator', 'companyId': None, 'active': 'Active'}
        with st.engine.begin() as c:
            st.put_record(c, 'users', uid, None, u, SYSTEM, 'Created')
            c.execute(insert(st.users_auth).values(user_id=uid, email=a.email.lower(), pw_hash=hash_pw(a.password), must_change=True))
            st.write_audit(c, None, SYSTEM, 'Created administrator', 'users', a.email)
        print('Super Administrator created:', a.email, '(must change password at first sign-in)')
    elif a.cmd == 'seed-sample':
        pw = a.password or 'Sample-2026-demo'
        made = seed_sample(pw, a.file or SAMPLE)
        print('Sample project loaded. Sign-ins (password: %s):' % pw)
        for n, r, e in made:
            print('  %-34s %-24s %s' % (e, r, n))
    elif a.cmd == 'set-password':
        with st.engine.begin() as c:
            n = c.execute(update(st.users_auth).where(func.lower(st.users_auth.c.email) == a.email.lower()).values(pw_hash=hash_pw(a.password), failed=0, locked_until=None)).rowcount
        print('Password reset' if n else 'No user with that e-mail')
    elif a.cmd == 'backup':
        from .jobs import write_backup, verify_backup
        print(verify_backup(write_backup('cli')))
    elif a.cmd == 'verify-audit':
        with st.engine.begin() as c:
            print(st.verify_audit_chain(c))


if __name__ == '__main__':
    main()
