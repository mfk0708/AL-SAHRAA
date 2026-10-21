"""Database layer: PostgreSQL (production) or SQLite (single-user / tests) via SQLAlchemy Core.

Business records are stored as JSON documents in one `records` table keyed by
(collection, id) with company ownership, optimistic version, a global change
sequence and soft-removal tombstones.  Every write also lands in the append-only
`record_history` table, and every action in the hash-chained `audit_log`.
"""
import hashlib, json, datetime as dt
from sqlalchemy import (create_engine, MetaData, Table, Column, String, Integer, BigInteger, Boolean, Text, DateTime,
                        JSON, Float, Index, PrimaryKeyConstraint, select, insert, update, func, event)
from sqlalchemy.dialects.postgresql import JSONB
from . import config

SCHEMA_VERSION = 1
engine = create_engine(config.DATABASE_URL, pool_pre_ping=True, future=True,
                       **({'connect_args': {'check_same_thread': False}} if config.DATABASE_URL.startswith('sqlite') else {}))
IS_PG = engine.dialect.name == 'postgresql'
if not IS_PG:
    @event.listens_for(engine, 'connect')
    def _sqlite_pragmas(con, _):
        cur = con.cursor(); cur.execute('PRAGMA journal_mode=WAL'); cur.execute('PRAGMA foreign_keys=ON'); cur.close()

J = JSON().with_variant(JSONB(), 'postgresql')
md = MetaData()
now = lambda: dt.datetime.now(dt.timezone.utc)

records = Table('records', md,
    Column('coll', String(40), nullable=False), Column('id', String(80), nullable=False),
    Column('company_id', String(80), index=True), Column('data', J, nullable=False),
    Column('version', Integer, nullable=False, default=1), Column('seq', BigInteger, nullable=False, index=True),
    Column('removed', Boolean, nullable=False, default=False),
    Column('created_at', DateTime(timezone=True), default=now), Column('updated_at', DateTime(timezone=True), default=now),
    Column('updated_by', String(120)), PrimaryKeyConstraint('coll', 'id'), Index('ix_records_company_coll', 'company_id', 'coll'))
record_history = Table('record_history', md,
    Column('hid', BigInteger().with_variant(Integer, 'sqlite'), primary_key=True, autoincrement=True),
    Column('coll', String(40)), Column('id', String(80)), Column('company_id', String(80), index=True), Column('version', Integer),
    Column('action', String(20)), Column('data', J), Column('user_id', String(80)), Column('user_name', String(120)),
    Column('at', DateTime(timezone=True), default=now), Index('ix_hist_rec', 'coll', 'id'))
audit_log = Table('audit_log', md,
    Column('aid', BigInteger().with_variant(Integer, 'sqlite'), primary_key=True, autoincrement=True),
    Column('at', DateTime(timezone=True), default=now), Column('company_id', String(80), index=True),
    Column('user_id', String(80)), Column('user_name', String(120)), Column('role', String(60)),
    Column('action', String(120)), Column('entity', String(120)), Column('detail', Text),
    Column('ip', String(64)), Column('prev_hash', String(64)), Column('hash', String(64)))
users_auth = Table('users_auth', md,
    Column('user_id', String(80), primary_key=True), Column('email', String(200), unique=True, nullable=False),
    Column('pw_hash', String(300)), Column('failed', Integer, default=0), Column('locked_until', DateTime(timezone=True)),
    Column('must_change', Boolean, default=False), Column('last_login', DateTime(timezone=True)))
sessions = Table('sessions', md,
    Column('token_hash', String(64), primary_key=True), Column('user_id', String(80), index=True),
    Column('created', DateTime(timezone=True), default=now), Column('last_seen', DateTime(timezone=True), default=now),
    Column('expires', DateTime(timezone=True)), Column('ip', String(64)), Column('ua', String(300)))
files = Table('files', md,
    Column('doc_id', String(80), primary_key=True), Column('company_id', String(80), index=True), Column('name', String(300)),
    Column('type', String(120)), Column('size', BigInteger), Column('sha256', String(64)), Column('path', String(500)),
    Column('at', DateTime(timezone=True), default=now), Column('by', String(120)))
workspace = Table('workspace', md,
    Column('key', String(120), primary_key=True), Column('data', J), Column('version', Integer, default=1),
    Column('updated_at', DateTime(timezone=True), default=now), Column('updated_by', String(120)))
schedules = Table('schedules', md,
    Column('id', String(40), primary_key=True), Column('company_id', String(80), index=True), Column('name', String(200)),
    Column('recipients', Text), Column('frequency', String(20)), Column('hour', Integer), Column('weekday', Integer), Column('monthday', Integer),
    Column('active', Boolean, default=True), Column('last_run', DateTime(timezone=True)), Column('last_status', Text),
    Column('created_by', String(120)), Column('created_at', DateTime(timezone=True), default=now))
ai_usage = Table('ai_usage', md,
    Column('id', BigInteger().with_variant(Integer, 'sqlite'), primary_key=True, autoincrement=True),
    Column('company_id', String(80), index=True), Column('user_id', String(80)), Column('at', DateTime(timezone=True), default=now),
    Column('tokens_in', Integer, default=0), Column('tokens_out', Integer, default=0), Column('ok', Boolean), Column('detail', Text))
counters = Table('counters', md, Column('name', String(40), primary_key=True), Column('v', BigInteger, nullable=False))
schema_meta = Table('schema_meta', md, Column('version', Integer, primary_key=True), Column('applied_at', DateTime(timezone=True), default=now))
req_metrics = Table('req_metrics', md,
    Column('id', BigInteger().with_variant(Integer, 'sqlite'), primary_key=True, autoincrement=True),
    Column('at', DateTime(timezone=True), default=now), Column('path', String(200)), Column('status', Integer), Column('ms', Float))


def init_db():
    md.create_all(engine)
    with engine.begin() as c:
        if not c.execute(select(counters).where(counters.c.name == 'seq')).first():
            c.execute(insert(counters).values(name='seq', v=0))
        if not c.execute(select(schema_meta).where(schema_meta.c.version == SCHEMA_VERSION)).first():
            c.execute(insert(schema_meta).values(version=SCHEMA_VERSION))


def next_seq(c):
    c.execute(update(counters).where(counters.c.name == 'seq').values(v=counters.c.v + 1))
    return c.execute(select(counters.c.v).where(counters.c.name == 'seq')).scalar_one()


def _h(prev, row):
    return hashlib.sha256((prev + json.dumps(row, sort_keys=True, default=str)).encode()).hexdigest()


def write_audit(c, company_id, user, action, entity, detail='', ip=''):
    """Append to the hash-chained audit log (tamper-evident: each row hashes the previous)."""
    if IS_PG:
        c.exec_driver_sql('LOCK TABLE audit_log IN SHARE ROW EXCLUSIVE MODE')
    prev = c.execute(select(audit_log.c.hash).order_by(audit_log.c.aid.desc()).limit(1)).scalar() or '0' * 64
    at = now()
    row = {'at': at.isoformat(), 'company_id': company_id, 'user_id': (user or {}).get('id'), 'user_name': (user or {}).get('name', 'system'),
           'role': (user or {}).get('role', ''), 'action': str(action)[:120], 'entity': str(entity)[:120], 'detail': str(detail or '')[:4000]}
    c.execute(insert(audit_log).values(at=at, company_id=company_id, user_id=row['user_id'], user_name=row['user_name'], role=row['role'],
                                       action=row['action'], entity=row['entity'], detail=row['detail'], ip=ip, prev_hash=prev, hash=_h(prev, row)))


def verify_audit_chain(c, limit=None):
    prev = '0' * 64; n = 0; bad = []
    for r in c.execute(select(audit_log).order_by(audit_log.c.aid)):
        at = (r.at if r.at.tzinfo else r.at.replace(tzinfo=dt.timezone.utc)).astimezone(dt.timezone.utc)
        row = {'at': at.isoformat(), 'company_id': r.company_id, 'user_id': r.user_id, 'user_name': r.user_name, 'role': r.role,
               'action': r.action, 'entity': r.entity, 'detail': r.detail}
        if r.prev_hash != prev or r.hash != _h(prev, row):
            bad.append(r.aid)
        prev = r.hash; n += 1
    return {'rows': n, 'broken': bad}


def get_record(c, coll, id_):
    return c.execute(select(records).where(records.c.coll == coll, records.c.id == id_)).first()


def put_record(c, coll, id_, company_id, data, user, action, existing=None):
    """Insert or update one record, bump version and sequence, write history."""
    seq = next_seq(c); t = now()
    if existing is None:
        c.execute(insert(records).values(coll=coll, id=id_, company_id=company_id, data=data, version=1, seq=seq, removed=False,
                                         created_at=t, updated_at=t, updated_by=user.get('name')))
        ver = 1
    else:
        ver = existing.version + 1
        c.execute(update(records).where(records.c.coll == coll, records.c.id == id_).values(
            data=data, version=ver, seq=seq, removed=(action == 'Removed'), updated_at=t, updated_by=user.get('name')))
    c.execute(insert(record_history).values(coll=coll, id=id_, company_id=company_id, version=ver, action=action, data=data,
                                            user_id=user.get('id'), user_name=user.get('name'), at=t))
    return ver, seq
