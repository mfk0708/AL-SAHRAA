"""Runtime configuration, read from environment variables (see cat.env.example).
Empty values fall back to the defaults."""
import os
from pathlib import Path


def env(k, d=''):
    v = os.environ.get(k)
    return d if v is None or str(v).strip() == '' else str(v).strip()


_ROOT = Path(__file__).resolve().parent.parent
BASE = Path(env('CAT_DATA_DIR', str(_ROOT / 'data')))
if not BASE.is_absolute():
    BASE = (_ROOT / BASE).resolve()
DATABASE_URL = env('DATABASE_URL', 'sqlite:///' + str(BASE / 'cat.db'))
FILES_DIR = Path(env('CAT_FILES_DIR', str(BASE / 'files')))
BACKUP_DIR = Path(env('CAT_BACKUP_DIR', str(BASE / 'backups')))
WEB_INDEX = Path(env('CAT_WEB_INDEX', str(_ROOT / 'web' / 'index.html')))
COOKIE_SECURE = env('CAT_COOKIE_SECURE', '0') == '1' or bool(env('CAT_SSL_CERT'))
SESSION_HOURS = float(env('CAT_SESSION_HOURS', '12'))
MAX_UPLOAD_MB = int(env('CAT_MAX_UPLOAD_MB', '50'))
BACKUP_KEEP = int(env('CAT_BACKUP_KEEP', '14'))
BACKUP_HOUR = int(env('CAT_BACKUP_HOUR', '2'))
ANTHROPIC_API_KEY = env('ANTHROPIC_API_KEY')
ANTHROPIC_BASE_URL = env('ANTHROPIC_BASE_URL', 'https://api.anthropic.com')
SMTP_HOST = env('SMTP_HOST')
SMTP_PORT = int(env('SMTP_PORT', '587'))
SMTP_USER = env('SMTP_USER')
SMTP_PASSWORD = env('SMTP_PASSWORD')
SMTP_FROM = env('SMTP_FROM', 'cat-reports@localhost')
SMTP_TLS = env('SMTP_TLS', '1') == '1'
RUN_JOBS = env('CAT_RUN_JOBS', '1') == '1'
APP_VERSION = '3.2.0'
for d in (BASE, FILES_DIR, BACKUP_DIR):
    d.mkdir(parents=True, exist_ok=True)
