def run(target, opts):
    from utils import resolve_hostname, get_cert
    findings=[]
    dns = resolve_hostname(target)
    cert = get_cert(target)
    if isinstance(cert, dict) and cert.get('notAfter'):
        findings.append({'severity':'info','title':'TLS expiry','detail':str(cert.get('notAfter'))})
    return {'dns':dns,'tls':cert,'findings':findings}