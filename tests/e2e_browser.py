"""End-to-end browser test against a running server (default http://localhost:8800) with the sample project loaded."""
import asyncio, json, sys, os
from playwright.async_api import async_playwright
URL = os.environ.get('CAT_URL', 'http://localhost:8800/')
PW = 'Sample-2026-demo'
SH = os.environ.get('CAT_SHOTS', '/tmp')
R = []
EXTERNAL = []
from urllib.parse import urlparse
HOST = urlparse(URL).hostname
def T(n, name, ok, detail=''):
    R.append((n, name, bool(ok), detail)); print(('PASS' if ok else 'FAIL'), n, name, '|', str(detail)[:250], flush=True)

async def login(ctx, email, pw=PW):
    pg = await ctx.new_page(); errs = []
    pg.on('pageerror', lambda e: errs.append(str(e)))
    await pg.goto(URL); await pg.wait_for_selector('#lg_email', timeout=15000)
    await pg.fill('#lg_email', email); await pg.fill('#lg_pw', pw); await pg.click('#lg_go')
    await pg.wait_for_selector('#page', timeout=20000); await pg.wait_for_timeout(800)
    pg.errs = errs
    return pg

async def settle(pg, ms=900):
    await pg.wait_for_timeout(ms)
    await pg.evaluate("syncNow()"); await pg.wait_for_timeout(300)

async def guard(route):
    u = route.request.url
    if urlparse(u).hostname not in (HOST, None) and not u.startswith(('data:', 'blob:')):
        EXTERNAL.append(u); await route.abort()  # the server edition must not need the internet
    else:
        await route.continue_()

async def main():
    async with async_playwright() as p:
        b0 = await p.chromium.launch(executable_path=os.environ.get('CHROME_PATH') or None)
        class B:  # every browser context blocks requests to other hosts
            async def new_context(self, **kw):
                c = await b0.new_context(**kw); await c.route('**/*', guard); return c
            async def close(self): await b0.close()
        b = B()
        ctxA = await b.new_context(viewport={'width': 1400, 'height': 1000})
        # 1 login page + wrong password
        pg = await ctxA.new_page(); await pg.goto(URL); await pg.wait_for_selector('#lg_email')
        await pg.fill('#lg_email', 'example.admin@sample.cat.test'); await pg.fill('#lg_pw', 'wrong-password-1'); await pg.click('#lg_go'); await pg.wait_for_timeout(800)
        msg = await pg.inner_text('#lg_msg'); await pg.screenshot(path=SH + '/srv_login.png')
        T('E1', 'Sign-in page shown; wrong password refused', 'incorrect' in msg, msg)
        await pg.close()
        # 2 admin sign in, dashboard, reconciliation
        A = await login(ctxA, 'example.admin@sample.cat.test')
        await A.wait_for_function("document.getElementById('srvRecon') && !document.getElementById('srvRecon').querySelector('.spin')", timeout=15000)
        rec = await A.inner_text('#srvRecon'); await A.wait_for_timeout(1200); await A.screenshot(path=SH + '/srv_dashboard.png')
        who = await A.evaluate("me().name + ' / ' + me().role + ' / ' + (company()||{}).name")
        T('E2', 'Company administrator signs in; dashboard loads from the server', 'Example Admin' in who and 'Example Main Contractor' in who, who)
        T('E3', 'Server cross-check: dashboard KPIs match the database totals', '8/8' in rec, rec)
        # 3 create a variation, persists after reload
        pkid = await A.evaluate("co('packages').find(p=>p.name==='Earthworks').id")
        await A.evaluate(f"(()=>{{ const v = add('variations', {{ packageId: '{pkid}', ref: 'VO-E2E', date: today(), description: 'E2E variation', submitted: 12345, status: 'Submitted' }}); audit('Created','variations','VO-E2E'); save(); }})()")
        await settle(A)
        await A.reload(); await A.wait_for_selector('#page'); await A.wait_for_timeout(1000)
        has = await A.evaluate("co('variations').some(v=>v.ref==='VO-E2E' && v.submitted===12345)")
        T('E4', 'New record saved to the server survives a page reload (session kept)', has)
        # 4 second user sees it; read-only user cannot change
        ctxV = await b.new_context(); V = await login(ctxV, 'example.viewer@sample.cat.test')
        seen = await V.evaluate("co('variations').some(v=>v.ref==='VO-E2E')")
        await V.evaluate("(()=>{ const p = co('projects')[0]; p.name = 'Changed by viewer'; save(); })()"); await settle(V, 1200)
        still = await V.evaluate("co('projects').some(p=>p.name==='Changed by viewer')")
        await V.reload(); await V.wait_for_selector('#page'); await V.wait_for_timeout(800)
        still2 = await V.evaluate("co('projects').some(p=>p.name==='Changed by viewer')")
        T('E5', 'Other users see saved records; a read-only user cannot change data on the server', seen and not still2, f'visible={seen}; local edit kept only in that browser until reload={still}; after reload={still2}')
        # 5 live update via polling
        await A.evaluate("(()=>{ const v = co('variations').find(v=>v.ref==='VO-E2E'); upd('variations', v.id, { description: 'E2E variation – updated' }); save(); })()"); await settle(A)
        await V.evaluate("pollChanges()"); await V.wait_for_timeout(800)
        upd = await V.evaluate("co('variations').find(v=>v.ref==='VO-E2E').description")
        T('E6', 'Changes by one user reach other signed-in users (polling)', upd.endswith('updated'), upd)
        # 6 conflict
        ctxC = await b.new_context(); C = await login(ctxC, 'example.commercial.manager@sample.cat.test')
        await A.evaluate("(()=>{ const v = co('variations').find(v=>v.ref==='VO-E2E'); v.assessed = 10000; save(); })()"); await settle(A)
        await C.evaluate("(()=>{ const v = co('variations').find(v=>v.ref==='VO-E2E'); v.assessed = 11111; save(); })()"); await settle(C, 1200)
        cval = await C.evaluate("co('variations').find(v=>v.ref==='VO-E2E').assessed")
        T('E7', 'Simultaneous edits: the later stale edit is refused and the saved value restored', cval == 10000, f'commercial manager now sees assessed={cval}')
        # 7 company isolation
        ctxB = await b.new_context(); B = await login(ctxB, 'example.b.admin@sample.cat.test')
        bp = await B.evaluate("JSON.stringify({companies:S.companies.map(c=>c.name), projects:S.projects.map(p=>p.name), vars:S.variations.length})")
        leak = await B.evaluate("fetch('/api/history/variations/' + 'x').then(r=>r.status)")
        T('E8', 'Company B user sees no Company A data', 'Main Contractor' not in bp and json.loads(bp)['vars'] == 0, bp)
        # 8 subcontractor user cannot certify
        ctxS = await b.new_context(); Su = await login(ctxS, 'example.subcontractor.user@sample.cat.test')
        await Su.evaluate("(()=>{ const p = co('payments').find(p=>p.status==='Under assessment'); p.status='Certified'; save(); })()"); await settle(Su, 1200)
        st = await Su.evaluate("co('payments').some(p=>p.appNo===3 && p.status==='Certified' && co('packages').find(k=>k.id===p.packageId).name==='Earthworks')")
        T('E9', 'Subcontractor user cannot certify a payment (server refuses)', not st)
        # 9 upload original file and fetch it back
        up = await A.evaluate("""(async()=>{ await need('jspdf'); const d=new window.jspdf.jsPDF(); let y=15; CATSamples.baseline.split('\\n').slice(0,120).forEach(l=>{ d.splitTextToSize(l,180).forEach(x=>{ if(y>280){d.addPage();y=15;} d.text(x,10,y); y+=6; }); }); const f=new File([d.output('blob')],'E2E-baseline.pdf',{type:'application/pdf'}); UI.tab.library='upload'; go('library'); await new Promise(r=>setTimeout(r,600)); if(!document.getElementById('up_cat')) return {status:'no upload form', html: document.getElementById('page').innerText.slice(0,200)}; await handleFiles([f]); for(let i=0;i<60;i++){ await new Promise(r=>setTimeout(r,500)); const doc=co('docs').find(x=>x.fileName==='E2E-baseline.pdf'||x.title&&x.title.includes('E2E-baseline')); if(doc && doc.serverStored) { const r=await fetch('/api/files/'+doc.id); const b=await r.blob(); return {status:r.status,size:b.size,id:doc.id}; } } return {status:'timeout', docs: co('docs').map(d=>d.title+'|'+d.fileName+'|'+d.serverStored)}; })()""")
        T('E10', 'Uploaded original is stored on the server and downloadable', up.get('status') == 200 and up.get('size', 0) > 1000, up)
        bstat = await B.evaluate(f"fetch('/api/files/{up.get('id','x')}').then(r=>r.status)")
        T('E11', 'Company B cannot download Company A originals', bstat == 404, bstat)
        # 10 run in-app automated suite in server mode, check no test data leaks to the server
        before = await A.evaluate("fetch('/api/admin/status').then(r=>r.json()).then(j=>j.records)")
        await A.evaluate("go('settings')"); await A.evaluate("runTests()")
        res = None
        for i in range(300):
            await A.wait_for_timeout(500)
            res = await A.evaluate("UI.tests && !TESTING ? JSON.stringify(UI.tests) : ''")
            if res: break
        res = json.loads(res or '[]'); await settle(A, 1500)
        after = await A.evaluate("fetch('/api/admin/status').then(r=>r.json()).then(j=>j.records)")
        fails = [f"{x['n']} {x['name']}: {x.get('detail','')[:120]}" for x in res if x['ok'] is not True]
        T('E12', 'In-app automated suite passes when running against the server', len(res) >= 79 and not fails, f"{sum(1 for x in res if x['ok'] is True)}/{len(res)} passed; " + '; '.join(fails[:4]))
        T('E13', 'Test fixtures never reach the server database', before == after, f'records before {before}, after {after}')
        # 11 module status after test run, dashboard registers
        await A.reload(); await A.wait_for_selector('#page'); await A.wait_for_timeout(800)
        await A.evaluate("go('status')"); await A.wait_for_timeout(500)
        cnt = await A.evaluate("JSON.stringify(MODULES.map(moduleStatus).reduce((o,m)=>(o[m.status]=(o[m.status]||0)+1,o),{}))")
        await A.screenshot(path=SH + '/srv_status.png', full_page=True)
        T('E14', 'Module status reflects server integration and synced test results', 'Awaiting Integration' not in cnt, cnt)
        # 12 settings server tab
        await A.evaluate("UI.tab.settings='server'; go('settings')"); await A.wait_for_timeout(2500)
        stxt = await A.inner_text('#srvStatus'); await A.screenshot(path=SH + '/srv_settings.png', full_page=True)
        T('E15', 'Server status, audit chain and backups visible to administrators', ('postgresql' in stxt or 'sqlite' in stxt) and 'Intact' in stxt, stxt[:200].replace('\n', ' '))
        # 12b OCR of a scanned page, using only the server's own OCR files
        ocr = await A.evaluate("""(async()=>{ await need('jspdf'); const cv=document.createElement('canvas'); cv.width=1200; cv.height=500; const g=cv.getContext('2d'); g.fillStyle='#fff'; g.fillRect(0,0,1200,500); g.fillStyle='#000'; g.font='40px serif';
          ['1. Payment','The Contractor shall pay the Subcontractor within 30 days','2. Retention','Retention of 10 percent shall be deducted'].forEach((t,i)=>g.fillText(t,40,80+i*90));
          const d=new window.jspdf.jsPDF(); d.addImage(cv.toDataURL('image/png'),'PNG',10,10,190,80); S.settings.ocr=true;
          const r=await extractFile(new File([d.output('blob')],'scan.pdf')); return {conf:r.extraction.ocrConfidence, text:r.pages.map(p=>p.text).join(' ').slice(0,200)}; })()""")
        T('E18', 'Scanned page is read by OCR served from this server (no internet)', 'Subcontractor' in ocr.get('text', '') and 'Retention' in ocr.get('text', ''), ocr)
        T('E19', 'The application made no request to any other host', not EXTERNAL, EXTERNAL[:5])
        # 13 sign out
        await A.evaluate("signOut()"); await A.wait_for_selector('#lg_email', timeout=10000)
        T('E16', 'Sign out returns to the sign-in page', True)
        errs = A.errs + V.errs + B.errs + C.errs + Su.errs
        T('E17', 'No JavaScript errors in any session', not errs, errs[:3])
        mob = await (await b.new_context(viewport={'width': 390, 'height': 844})).new_page(); await mob.goto(URL); await mob.wait_for_selector('#lg_email'); await mob.screenshot(path=SH + '/srv_login_mobile.png')
        await b.close()
    print('E2E', sum(1 for r in R if r[2]), 'of', len(R), 'passed')
    json.dump([dict(n=r[0], name=r[1], ok=r[2], detail=str(r[3])) for r in R], open(SH + '/e2e_results.json', 'w'), indent=1)
asyncio.run(main())
