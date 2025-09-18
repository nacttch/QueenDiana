import time
from modules import http_snap, sensitive_scan, cred_policy, phish_detector, csp_analyzer, sitemap_crawl, open_redirect, indicators, cms_waf, whois_dns_tls
from reporter import make_full_report

class Engine:
    def run(self, target, opts, mode='full'):
        report = {'target':target,'timestamp':time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'findings':[], 'modules':{}}
        snap = http_snap.run(target, opts); report['modules']['http']=snap; report['findings']+=snap.get('findings',[])
        csp = csp_analyzer.run(target, opts, snap); report['modules']['csp']=csp; report['findings']+=csp.get('findings',[])
        if mode in ['sensitive','full']:
            s = sensitive_scan.run(target, opts); report['modules']['sensitive']=s; report['findings']+=s.get('findings',[])
        if mode in ['cred','full']:
            c = cred_policy.run(target, opts); report['modules']['credentials']=c; report['findings']+=c.get('findings',[])
        if mode in ['phish','full']:
            p = phish_detector.run(target, opts, snap); report['modules']['phish']=p; report['findings']+=p.get('findings',[])
        if mode in ['sitemap','full']:
            sm = sitemap_crawl.run(target, opts); report['modules']['sitemap']=sm; report['findings']+=sm.get('findings',[])
        if mode in ['open_redirect','full']:
            o = open_redirect.run(target, opts); report['modules']['open_redirect']=o; report['findings']+=o.get('findings',[])
        if mode in ['indicators','full']:
            ind = indicators.run(target, opts); report['modules']['indicators']=ind; report['findings']+=ind.get('findings',[])
        cms = cms_waf.run(target, opts); report['modules']['cms']=cms; report['findings']+=cms.get('findings',[])
        w = whois_dns_tls.run(target, opts); report['modules']['whois_dns_tls']=w; report['findings']+=w.get('findings',[])
        make_full_report('report', target, report.get('findings',[]), raw_http=report.get('modules').get('http',{}))
        return report
