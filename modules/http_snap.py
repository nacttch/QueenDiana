def run(target, opts):
    from utils import safe_get
    findings=[]
    r = safe_get(target, timeout=opts.get('timeout',10), retries=opts.get('retries',1), delay=opts.get('delay',0.5))
    snap={'ok':r.get('ok',False),'status':r.get('status'),'headers':r.get('headers'),'url':r.get('url')}
    if r.get('ok'):
        headers = {k.lower():v for k,v in (r.get('headers') or {}).items()}
        if 'strict-transport-security' not in headers:
            findings.append({'severity':'medium','title':'Missing HSTS','detail':'Add Strict-Transport-Security header','recommendation':'HSTS'})
    else:
        findings.append({'severity':'high','title':'HTTP fetch failed','detail':str(r.get('error'))})
    snap['body']=r.get('text','') if r.get('ok') else ''
    return {'snapshot':snap,'findings':findings}