def run(target, opts):
    from utils import safe_get
    findings=[]
    # basic cms detection
    checks = {'wp-login':'/wp-login.php','joom':'/administrator/','drupal':'/user/login'}
    detected=[]
    for k,p in checks.items():
        r = safe_get(target.rstrip('/')+p, timeout=6, retries=0, delay=0.2)
        if r.get('ok') and r.get('status')==200:
            detected.append(k)
            findings.append({'severity':'info','title':'CMS endpoint','detail':p})
    # simple WAF header heuristic
    r = safe_get(target, timeout=6, retries=0, delay=0.2)
    headers = r.get('headers') or {}
    if any('akamai' in v.lower() or 'cloudflare' in v.lower() for v in headers.values()):
        findings.append({'severity':'info','title':'WAF/proxy detected','detail':str(headers.get('server',''))})
    return {'detected':detected,'findings':findings}