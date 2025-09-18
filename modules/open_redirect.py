def run(target, opts):
    from utils import safe_get
    findings=[]
    params = ['next','url','redirect','r','return']
    for p in params:
        test = target + ('?' if '?' not in target else '&') + f"{p}=https://example.com/qd_test"
        rr = safe_get(test, timeout=6, retries=0, delay=0.2, allow_redirects=False)
        if rr.get('ok') and rr.get('status') in (301,302,303,307,308):
            loc = rr.get('headers',{}).get('Location') or rr.get('headers',{}).get('location') or ''
            findings.append({'severity':'high','title':'Open redirect','detail':f'{p} -> {loc}'})
    return {'findings':findings}