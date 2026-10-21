#!/usr/bin/env bash
# =====================================================================
#  Contract Assessment Tools – Linux server installer (systemd)
#  Tested on Ubuntu/Debian; works on RHEL/Rocky/Alma 8+ with Python 3.11+.
#
#  sudo ./install/install_linux.sh [options]
#    --prefix DIR          install folder            (default /opt/contract-assessment-tools)
#    --data DIR            data folder               (default /var/lib/contract-assessment-tools)
#    --port N              HTTP port                 (default 8000)
#    --database-url URL    PostgreSQL URL            (default: SQLite in the data folder)
#    --no-sample           start with an empty database (production)
#    --python PATH         Python 3.11–3.13 to use   (default: newest python3.1x found)
#    --no-service          install only; do not create/start the systemd service
#  Re-running the installer upgrades the program and keeps settings and data.
# =====================================================================
set -euo pipefail
PREFIX=/opt/contract-assessment-tools; DATA=/var/lib/contract-assessment-tools; ETC=/etc/contract-assessment-tools
PORT=8000; DBURL=""; SAMPLE=1; PY=""; SERVICE=1; SVC=contract-assessment-tools; RUNUSER=cat
while [ $# -gt 0 ]; do case "$1" in
  --prefix) PREFIX="$2"; shift 2;; --data) DATA="$2"; shift 2;; --port) PORT="$2"; shift 2;;
  --database-url) DBURL="$2"; shift 2;; --no-sample) SAMPLE=0; shift;; --python) PY="$2"; shift 2;;
  --no-service) SERVICE=0; shift;; --etc) ETC="$2"; shift 2;; -h|--help) sed -n '2,17p' "$0"; exit 0;;
  *) echo "Unknown option $1"; exit 2;; esac; done
SRC="$(cd "$(dirname "$0")/.." && pwd)"
say() { printf '\n\033[1m%s\033[0m\n' "$*"; }
[ "$(id -u)" = 0 ] || { echo "Run as root (sudo)."; exit 1; }

say "1/7  Checking Python"
if [ -z "$PY" ]; then for c in python3.13 python3.12 python3.11 python3; do
  if command -v $c >/dev/null && $c -c 'import sys; sys.exit(0 if (3,11)<=sys.version_info[:2]<=(3,13) else 1)' 2>/dev/null; then PY=$(command -v $c); break; fi; done; fi
[ -n "$PY" ] || { echo "Python 3.11, 3.12 or 3.13 is required (e.g. 'apt install python3.12 python3.12-venv' or 'dnf install python3.11'). Or use Docker."; exit 1; }
$PY -c 'import venv, ensurepip' 2>/dev/null || { echo "The Python 'venv' module is missing. Install it (Debian/Ubuntu: apt install python3-venv  or  python3.12-venv)."; exit 1; }
echo "Using $PY ($($PY -V))"

say "2/7  Creating service account and folders"
id -u $RUNUSER >/dev/null 2>&1 || useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin $RUNUSER
mkdir -p "$PREFIX" "$DATA" "$ETC" "$DATA/logs"

say "3/7  Copying program files to $PREFIX"
rm -rf "$PREFIX/cat_server" "$PREFIX/web"
cp -r "$SRC/cat_server" "$SRC/web" "$SRC/sample" "$SRC/requirements.txt" "$SRC/README.md" "$SRC/cat.env.example" "$PREFIX/"
[ -d "$SRC/install" ] && cp -r "$SRC/install" "$PREFIX/"
find "$PREFIX" -name __pycache__ -prune -exec rm -rf {} +

say "4/7  Installing Python packages"
[ -x "$PREFIX/.venv/bin/python" ] || $PY -m venv "$PREFIX/.venv"
WH="$SRC/wheels/linux-x64"; [ -d "$WH" ] || WH="$PREFIX/wheels/linux-x64"
if [ -d "$WH" ] && [ "$(uname -m)" = x86_64 ]; then
  echo "Offline install from $WH"; "$PREFIX/.venv/bin/pip" install -q --no-index --find-links "$WH" -r "$PREFIX/requirements.txt"
else
  echo "Installing from the Python Package Index"; "$PREFIX/.venv/bin/pip" install -q --upgrade pip >/dev/null 2>&1 || true
  "$PREFIX/.venv/bin/pip" install -q -r "$PREFIX/requirements.txt"
fi

say "5/7  Settings ($ETC/cat.env)"
if [ ! -f "$ETC/cat.env" ]; then
  sed -e "s#^CAT_PORT=.*#CAT_PORT=$PORT#" -e "s#^CAT_DATA_DIR=.*#CAT_DATA_DIR=$DATA#" -e "s#^SEED_SAMPLE=.*#SEED_SAMPLE=$SAMPLE#" \
      -e "s#^DATABASE_URL=.*#DATABASE_URL=$DBURL#" -e "s#^\# CAT_LOG_FILE=.*#\# CAT_LOG_FILE=$DATA/logs/server.log#" "$PREFIX/cat.env.example" > "$ETC/cat.env"
  echo "Created $ETC/cat.env"
else echo "Keeping existing $ETC/cat.env"; fi
chown -R root:$RUNUSER "$ETC"; chmod 750 "$ETC"; chmod 640 "$ETC/cat.env"
chown -R $RUNUSER:$RUNUSER "$DATA"; chmod 750 "$DATA"
chown -R root:root "$PREFIX"; chmod -R a+rX "$PREFIX"

say "6/7  Preparing the database"
( cd "$PREFIX" && runuser -u $RUNUSER -- env CAT_ENV_FILE="$ETC/cat.env" "$PREFIX/.venv/bin/python" -c "
import sys; sys.argv=['x']
from cat_server.run import load_env; import os; load_env(os.environ['CAT_ENV_FILE'])
from cat_server import store; store.init_db(); print('Database ready:', store.engine.url.render_as_string(hide_password=True))" )

if [ "$SERVICE" = 1 ]; then
  say "7/7  Creating and starting the systemd service '$SVC'"
  cat > /etc/systemd/system/$SVC.service <<UNIT
[Unit]
Description=Contract Assessment Tools
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
User=$RUNUSER
Group=$RUNUSER
WorkingDirectory=$PREFIX
Environment=CAT_ENV_FILE=$ETC/cat.env
ExecStart=$PREFIX/.venv/bin/python -m cat_server.run --env $ETC/cat.env
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=$DATA

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload; systemctl enable --now $SVC; systemctl restart $SVC
  for i in $(seq 1 30); do sleep 1; curl -fsS "http://127.0.0.1:$PORT/api/health" >/dev/null 2>&1 && break; done
  if curl -fsS "http://127.0.0.1:$PORT/api/health" >/dev/null 2>&1; then echo "Service is running."; else echo "Service did not answer yet – check: journalctl -u $SVC -n 50"; fi
else
  say "7/7  Service not created (--no-service). Start manually with:"
  echo "  sudo -u $RUNUSER CAT_ENV_FILE=$ETC/cat.env $PREFIX/.venv/bin/python -m cat_server.run --env $ETC/cat.env"
fi

say "Done."
echo "Open:      http://$(hostname -f 2>/dev/null || hostname):$PORT"
echo "Settings:  $ETC/cat.env   (restart after changes: systemctl restart $SVC)"
echo "Data:      $DATA          Logs: journalctl -u $SVC"
[ "$SAMPLE" = 1 ] && echo "Sample sign-in: example.admin@sample.cat.test / Sample-2026-demo   (see README for all accounts)"
[ "$SAMPLE" = 0 ] && echo "Create the first administrator:  cd $PREFIX && sudo -u $RUNUSER CAT_ENV_FILE=$ETC/cat.env .venv/bin/python -m cat_server.cli create-admin --email you@company.ae --name \"Your Name\" --password \"Temporary-Pass-2026\""
exit 0
