def run(target, opts):
    from utils import safe_get
    findings=[]
    sitemap = target.rstrip('/') + '/sitemap.xml'
    r = safe_get(sitemap, timeout=6, retries=0, delay=0.2)
    urls=[]
    if r.get('ok') and r.get('status')==200 and r.get('text'):
        import re
        urls = re.findall(r'<loc>([^<]+)</loc>', r.get('text'))
    if urls:
        findings.append({'severity':'info','title':'Sitemap','detail':f'{len(urls)} URLs'})
    return {'urls':urls,'findings':findings}