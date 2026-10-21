"""Server-side business rules: roles and permissions, company/project visibility,
write validation, redaction and dashboard KPI aggregation.  These rules are
enforced on every request regardless of what the browser sends."""
import re, datetime as dt

COLLS = ['companies', 'users', 'projects', 'packages', 'subs', 'docs', 'assessments', 'obligations', 'quotations', 'boq', 'negotiations',
         'payments', 'cashflow', 'variations', 'claims', 'delays', 'backcharges', 'risks', 'opportunities', 'performance', 'approvals',
         'letters', 'scopes', 'agreements', 'flows', 'scenarios', 'uat', 'dashViews', 'defects', 'audit']
GLOBAL_COLLS = {'companies', 'users', 'audit'}
ROLES = {
    'Super Administrator': {'edit': True, 'admin': True, 'users': True, 'all': True},
    'Company Administrator': {'edit': True, 'admin': True, 'users': True},
    'Commercial Manager': {'edit': True}, 'Contracts Manager': {'edit': True}, 'Quantity Surveyor': {'edit': True},
    'Procurement Manager': {'edit': True}, 'Project Manager': {'edit': True},
    'Subcontractor User': {'edit': True, 'only': ['payments', 'variations', 'claims', 'letters']},
    'Reviewer': {'edit': False}, 'Read-only User': {'edit': False},
}
CERT_ROLES = {'Super Administrator', 'Company Administrator', 'Commercial Manager'}
APPROVAL_ROLES = {'Reviewer', 'Commercial Manager', 'Contracts Manager', 'Project Manager', 'Company Administrator', 'Super Administrator',
                  'Quantity Surveyor', 'Procurement Manager'}
PROTECTED_KEYS = {'password', 'pw_hash', 'apiKey'}


class Denied(Exception):
    pass


def role_of(user):
    return ROLES.get((user or {}).get('role'), ROLES['Read-only User'])


def is_super(user):
    return (user or {}).get('role') == 'Super Administrator'


def active(user):
    return (user or {}).get('active', 'Active') != 'Suspended'


def can_write(user, coll, company_id, old, new):
    """Raise Denied with a reason if `user` may not write `new` (None = delete) over `old` in `coll`."""
    if not active(user):
        raise Denied('User is suspended')
    r = role_of(user); sup = is_super(user)
    if coll not in COLLS:
        raise Denied('Unknown collection ' + coll)
    rec = new if new is not None else old
    # company ownership
    if coll == 'companies':
        if old is None or new is None:
            if not sup: raise Denied('Only a Super Administrator can create or delete companies')
        elif not sup and (not r.get('admin') or rec.get('id') != user.get('companyId')):
            raise Denied('Only an administrator of this company can change it')
        return
    if coll == 'audit':
        if old is not None or new is None: raise Denied('Audit entries cannot be changed or deleted')
        if not sup and company_id not in (None, user.get('companyId')): raise Denied('Audit entry for another company')
        return
    if not sup and company_id != user.get('companyId'):
        raise Denied('Record belongs to another company')
    if old is not None and new is not None and (old.get('companyId') != new.get('companyId')) and coll != 'users':
        raise Denied('A record cannot be moved to another company')
    if coll == 'users':
        if not r.get('users'):
            raise Denied('Your role cannot manage users')
        target_role = (new or old or {}).get('role')
        if target_role == 'Super Administrator' and not sup:
            raise Denied('Only a Super Administrator can grant Super Administrator')
        if not sup and old is not None and old.get('companyId') != user.get('companyId'):
            raise Denied('User belongs to another company')
        if new is not None and old is not None and new.get('id') == user.get('id') and new.get('role') != old.get('role'):
            raise Denied('You cannot change your own role')
        return
    if coll == 'dashViews':
        owner = (new or old or {}).get('userId')
        if owner != user.get('id') and not r.get('admin'):
            raise Denied('Saved views can only be changed by their owner')
        return
    if coll == 'approvals':
        if user.get('role') not in APPROVAL_ROLES and not r.get('edit'):
            raise Denied('Your role cannot act on approvals')
        return
    if not r.get('edit'):
        raise Denied('Your role (%s) is read-only' % user.get('role'))
    if r.get('only') and coll not in r['only']:
        raise Denied('Your role (%s) cannot change %s' % (user.get('role'), coll))
    if coll == 'payments' and new is not None:
        newst = new.get('status'); oldst = (old or {}).get('status')
        if newst in ('Certified', 'Paid') and newst != oldst and user.get('role') not in CERT_ROLES:
            raise Denied('Only %s can certify or mark a payment paid' % ', '.join(sorted(CERT_ROLES)))
    if coll == 'variations' and new is not None and new.get('status') in ('Approved', 'Partially Approved') and new.get('approved') in ('', None):
        raise Denied('An approved variation needs an approved amount')
    if coll == 'docs' and old is not None and new is None and not r.get('admin'):
        raise Denied('Only administrators can permanently delete documents')


def allowed_projects(user, company_projects):
    """Mirror of the browser rule: a non-admin user with a project list only sees those projects."""
    keys = [k.strip().lower() for k in str(user.get('projects') or '').split(',') if k.strip()]
    if not keys or role_of(user).get('admin') or role_of(user).get('all'):
        return None
    return {p['id'] for p in company_projects if str(p.get('number', '')).lower() in keys or str(p.get('name', '')).lower() in keys}


def visible(user, coll, data, company_id, pk_project, allowed):
    if is_super(user):
        return True
    if coll == 'companies':
        return data.get('id') == user.get('companyId')
    if company_id != user.get('companyId'):
        return False
    if coll == 'dashViews' and data.get('userId') != user.get('id') and not data.get('shared'):
        return False
    if allowed is None:
        return True
    if coll == 'projects':
        return data.get('id') in allowed
    proj = data.get('projectId') or pk_project.get(data.get('packageId'))
    return proj is None or proj in allowed


def clean(data):
    return {k: v for k, v in (data or {}).items() if k not in PROTECTED_KEYS}


_RED = [(re.compile(r'[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}', re.I), '[REDACTED-EMAIL]'),
        (re.compile(r'\bAE\d{2}\s?(?:\d{3}\s?){6}\d\b', re.I), '[REDACTED-IBAN]'),
        (re.compile(r'\b(?:\+?971|00971|0)\s?(?:5\d|[2-9])[\s-]?\d{3}[\s-]?\d{4}\b'), '[REDACTED-PHONE]'),
        (re.compile(r'\b\d{15}\b'), '[REDACTED-TRN]')]


def redact(t):
    for rx, rep in _RED:
        t = rx.sub(rep, t)
    return t


# ---------------- KPI aggregation (server copy of the dashboard's core measures) ----------------
def num(v):
    try:
        return float(v) if v not in (None, '') else 0.0
    except (TypeError, ValueError):
        return 0.0


def kpis(rows, company):
    """rows: dict coll -> list of record dicts for ONE company (removed records excluded).
    Returns the money/count KPIs the browser dashboard shows for 'All time / no filters',
    computed independently on the server for reconciliation."""
    base = (company or {}).get('currency') or 'AED'
    fx = {x['ccy']: num(x.get('rate')) for x in (company or {}).get('fx') or [] if x.get('approvedBy') and num(x.get('rate')) > 0}
    projects = {p['id']: p for p in rows.get('projects', [])}
    pk = rows.get('packages', [])

    def rate(p):
        c = p.get('currency') or projects.get(p.get('projectId'), {}).get('currency') or base
        return 1.0 if c == base else fx.get(c)

    R = {p['id']: rate(p) for p in pk}
    M = lambda pid, v: num(v) * R[pid] if R.get(pid) else 0.0
    ids = set(R)
    vars_ = [v for v in rows.get('variations', []) if v.get('packageId') in ids]
    pays = [p for p in rows.get('payments', []) if p.get('packageId') in ids]
    claims = [c for c in rows.get('claims', []) if c.get('packageId') in ids]
    appr = [v for v in vars_ if v.get('status') in ('Approved', 'Partially Approved')]
    pend = [v for v in vars_ if v.get('status') in ('Identified', 'Notified', 'Submitted', 'Under assessment', 'Under Review')]
    cert = [p for p in pays if p.get('status') in ('Certified', 'Paid')]
    latest = {}
    for p in pays:
        if p.get('period', '') <= dt.date.today().isoformat():
            cur = latest.get(p['packageId'])
            if not cur or num(cur.get('appNo')) < num(p.get('appNo')):
                latest[p['packageId']] = p
    out = {
        'k03': len(pk),
        'k04': sum(M(p['id'], p.get('value')) for p in pk),
        'k05': sum(M(p['id'], p.get('value')) for p in pk) + sum(M(v['packageId'], v.get('approved')) for v in appr if not v.get('date') or v['date'][:10] <= dt.date.today().isoformat()),
        'k10': sum(M(v['packageId'], v.get('approved')) for v in appr),
        'k11': sum(M(v['packageId'], v.get('submitted')) for v in pend),
        'k12': len(claims),
        'k13': sum(M(p['packageId'], (p.get('calc') or {}).get('payable')) for p in cert) - sum(M(p['packageId'], p.get('paidAmount')) for p in pays),
        'k14': sum(M(p['packageId'], (p.get('calc') or {}).get('retentionHeld')) for p in latest.values()),
        'certified': sum(M(p['packageId'], (p.get('calc') or {}).get('payable')) for p in cert),
        'paid': sum(M(p['packageId'], p.get('paidAmount')) for p in pays),
        'excluded': [p['name'] for p in pk if not R.get(p['id'])],
        'currency': base,
    }
    return {k: (round(v, 2) if isinstance(v, float) else v) for k, v in out.items()}
