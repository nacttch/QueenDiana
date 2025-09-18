def run(target, opts):
    # Passive indicators for XSS/SQLi: look for reflection of simple payloads in body
    from utils import safe_get
    findings=[]
    payloads = ['<script>alert(1)</script>','\" onerror=alert(1)','\'"']
    r = safe_get(target, timeout=8, retries=0, delay=0.3)
    body = r.get('text','') if r.get('ok') else ''
    for p in payloads:
        if p in body:
            findings.append({'severity':'high','title':'Payload reflected','detail':p})
    return {'findings':findings}