def run(target, opts):
    from utils import safe_get
    import re
    findings=[]
    r = safe_get(target, timeout=10, retries=1, delay=0.5)
    body = r.get('text','') if r.get('ok') else ''
    forms = re.findall(r'<form[\s\S]*?</form>', body, flags=re.I)
    for form in forms:
        if 'password' in form.lower():
            findings.append({'severity':'info','title':'Login form detected','detail':form[:200]})
    if not findings:
        findings.append({'severity':'info','title':'No login form found','detail':''})
    return {'login_forms':len(forms),'findings':findings}