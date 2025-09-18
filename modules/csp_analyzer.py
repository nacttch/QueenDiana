def run(target, opts, snap):
    findings=[]
    headers = snap.get('snapshot',{}).get('headers') or {}
    csp = headers.get('content-security-policy') or headers.get('Content-Security-Policy') or ''
    if not csp:
        findings.append({'severity':'info','title':'No CSP detected','detail':'Consider adding CSP header'})
    else:
        if "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
            findings.append({'severity':'medium','title':'Unsafe CSP directives','detail':csp,'recommendation':'Remove unsafe-inline/unsafe-eval'})
    return {'csp':csp,'findings':findings}