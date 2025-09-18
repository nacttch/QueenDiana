def run(target, opts):
    from utils import safe_get
    findings=[]
    wl = opts.get('wordlist','wordlists/sensitive_paths.txt')
    try:
        paths = open(wl,'r',encoding='utf-8').read().splitlines()
    except:
        paths=['.env','config.php','.git/']
    base=target.rstrip('/')
    for p in paths:
        if not p: continue
        url = base + ('/' + p if not p.startswith('/') else p)
        r = safe_get(url, timeout=6, retries=0, delay=0.2)
        if r.get('ok') and r.get('status')==200:
            findings.append({'severity':'high','title':'Sensitive file','detail':url,'recommendation':'Restrict access'})
    return {'found':len(findings)>0 and findings or [], 'findings':findings}