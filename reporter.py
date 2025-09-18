import os, json, datetime
from jinja2 import Template

HTML_TEMPLATE = """<html><head><meta charset='utf-8'><title>Queen Diana Report</title>
<style>body{font-family:Arial;background:#0b1220;color:#e6f7ff;padding:18px} .box{background:#07121a;padding:18px;border-radius:8px}</style>
</head><body><div class="box"><h1>Queen Diana Report</h1><p>Target: {{target}}</p><h3>Summary</h3><pre>{{summary}}</pre><h3>Findings</h3>{% for f in findings %}<div><strong>[{{f.severity}}]</strong> {{f.title}} {% if f.detail %}- {{f.detail}}{% endif %}</div>{% endfor %}<h3>Raw</h3><pre>{{json}}</pre></div></body></html>"""

def save_report(outdir, target, findings, raw_http=None):
    os.makedirs(outdir, exist_ok=True)
    ts = datetime.datetime.utcnow().isoformat()+'Z'
    rep = {'target':target,'timestamp':ts,'findings':findings,'http':raw_http or {}}
    j = os.path.join(outdir,'report.json'); m = os.path.join(outdir,'report.md'); h = os.path.join(outdir,'report.html')
    with open(j,'w',encoding='utf-8') as f: json.dump(rep,f,ensure_ascii=False,indent=2)
    with open(m,'w',encoding='utf-8') as f:
        f.write(f"# Queen Diana Report\n\n**Target:** {target}\nGenerated: {ts}\n\n")
        for it in findings:
            f.write(f"- [{it.get('severity','info')}] {it.get('title')} - {it.get('detail','')}\n")
    with open(h,'w',encoding='utf-8') as f:
        f.write(Template(HTML_TEMPLATE).render(target=target, summary={'count':len(findings)}, findings=findings, json=json.dumps(rep,indent=2)))
    return {'json':j,'md':m,'html':h}

def make_full_report(outdir, target, findings, raw_http=None):
    ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    d = os.path.join(outdir, f"queen_diana_{ts}")
    os.makedirs(d, exist_ok=True)
    return save_report(d, target, findings, raw_http)

def render_from_json(path):
    with open(path,'r',encoding='utf-8') as f: rep = json.load(f)
    outdir = os.path.dirname(path)
    save_report(outdir, rep.get('target','unknown'), rep.get('findings',[]), raw_http=rep.get('http'))
    return {'json': os.path.join(outdir,'report.json'), 'html': os.path.join(outdir,'report.html')}
