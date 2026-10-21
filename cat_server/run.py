"""Server launcher used by the installers and the Docker image.

    python -m cat_server.run [--env PATH]

Reads settings from a KEY=VALUE file (default: cat.env in the install folder,
or the CAT_ENV_FILE environment variable), prepares the database, optionally
loads the sample project on an empty database, and starts the web server.
"""
import argparse, os, sys
from pathlib import Path


def load_env(path):
    if not path or not Path(path).exists():
        return False
    for line in Path(path).read_text(encoding='utf-8-sig').splitlines():
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        k, v = line.split('=', 1); k = k.strip(); v = v.strip().strip('"').strip("'")
        os.environ.setdefault(k, v)
    return True


def main(argv=None):
    here = Path(__file__).resolve().parent.parent
    ap = argparse.ArgumentParser(prog='cat_server.run')
    ap.add_argument('--env', default=os.environ.get('CAT_ENV_FILE') or str(here / 'cat.env'))
    a = ap.parse_args(argv)
    found = load_env(a.env)
    if os.environ.get('CAT_LOG_FILE'):  # used by the Windows service, which has no console
        Path(os.environ['CAT_LOG_FILE']).parent.mkdir(parents=True, exist_ok=True)
        sys.stdout = sys.stderr = open(os.environ['CAT_LOG_FILE'], 'a', buffering=1, encoding='utf-8')
    from . import config, store as st, cli  # imported after the environment is loaded
    from sqlalchemy import select, func
    st.init_db()
    with st.engine.connect() as c:
        empty = not c.execute(select(func.count()).select_from(st.records).where(st.records.c.coll == 'companies')).scalar()
    if empty and os.environ.get('SEED_SAMPLE', '0') == '1':
        made = cli.seed_sample(os.environ.get('SAMPLE_PASSWORD') or 'Sample-2026-demo')
        print('Sample project loaded (%d sign-in accounts, see README).' % len(made), flush=True)
    elif empty:
        print('Database is empty. Create the first administrator with:\n  python -m cat_server.cli create-admin --email you@company.ae --name "Your Name" --password "Temporary-Pass-2026"', flush=True)
    host = os.environ.get('CAT_HOST', '0.0.0.0'); port = int(os.environ.get('CAT_PORT', '8000'))
    cert, key = os.environ.get('CAT_SSL_CERT'), os.environ.get('CAT_SSL_KEY')
    print('Contract Assessment Tools %s · database %s · settings %s · listening on %s://%s:%d' % (
        config.APP_VERSION, st.engine.dialect.name, a.env if found else '(environment only)', 'https' if cert else 'http', host, port), flush=True)
    import uvicorn
    uvicorn.run('cat_server.main:app', host=host, port=port, workers=1, proxy_headers=True, forwarded_allow_ips=os.environ.get('CAT_TRUSTED_PROXIES', '127.0.0.1'),
                ssl_certfile=cert or None, ssl_keyfile=key or None, log_level=os.environ.get('CAT_LOG_LEVEL', 'info'))


if __name__ == '__main__':
    main()
