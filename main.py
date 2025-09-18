#!/usr/bin/env python3
# Queen Diana Pro100X - All-in-one Safe Recon CLI
from utils import color, norm_url
from engine import Engine
import json, time, os

BANNER = """


                                                                   ▄▄                             
  ▄▄█▀▀██▄                                            ▀███▀▀▀██▄   ██                             
▄██▀    ▀██▄                                            ██    ▀██▄                                
██▀      ▀██▀███  ▀███   ▄▄█▀██  ▄▄█▀██▀████████▄       ██     ▀█████  ▄█▀██▄ ▀████████▄  ▄█▀██▄  
██        ██  ██    ██  ▄█▀   ██▄█▀   ██ ██    ██       ██      ██ ██ ██   ██   ██    ██ ██   ██  
██▄      ▄██  ██    ██  ██▀▀▀▀▀▀██▀▀▀▀▀▀ ██    ██       ██     ▄██ ██  ▄█████   ██    ██  ▄█████  
▀██▄    ▄██▀  ██    ██  ██▄    ▄██▄    ▄ ██    ██       ██    ▄██▀ ██ ██   ██   ██    ██ ██   ██  
  ▀▀████▀▀    ▀████▀███▄ ▀█████▀ ▀█████▀████  ████▄   ▄████████▀ ▄████▄████▀██▄████  ████▄████▀██▄
      ███                                                                                         
       ▀████▀                                                                                     



                                          by @nacttch
"""

def print_banner():
    print(color(BANNER, 'cyan'))
    print(color('Legal: only test targets you own or have explicit permission. Advanced scans require opt-in.', 'yellow'))

def menu():
    print('\n1) Quick Snapshot (headers, TLS)')
    print('2) Sensitive paths scan')
    print('3) Credential/login analysis')
    print('4) Phishing + domain similarity')
    print('5) CSP analysis & security headers')
    print('6) Sitemap crawl')
    print('7) Passive XSS/SQLi indicators (non-exploit)')
    print('8) CMS & WAF detection')
    print('9) Run Full Audit')
    print('0) Exit')

def interactive():
    print_banner()
    target = input('Target (example.com or https://example.com): ').strip()
    if not target:
        print('No target'); return
    target = norm_url(target)
    engine = Engine()
    while True:
        menu()
        c = input('Choice: ').strip()
        if c == '0': break
        mode_map = {'1':'http','2':'sensitive','3':'cred','4':'phish','5':'csp','6':'sitemap','7':'indicators','8':'cms','9':'full'}
        mode = mode_map.get(c,'full')
        opts = {'timeout':10,'retries':1,'delay':0.6,'wordlist':'wordlists/sensitive_paths.txt','sitemap_depth':2}
        print(color(f'Running {mode} on {target}', 'yellow'))
        res = engine.run(target, opts, mode=mode)
        ts = time.strftime('%Y%m%d_%H%M%S')
        out = os.path.join('report', f'queen_diana_pro100x_{ts}.json')
        with open(out,'w',encoding='utf-8') as f:
            json.dump(res, f, ensure_ascii=False, indent=2)
        print(color(f'Report saved -> {out}', 'green'))

if __name__ == '__main__':
    interactive()
