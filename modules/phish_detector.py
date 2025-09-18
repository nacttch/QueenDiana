# modules/phish_detector.py
"""
Robust Phishing heuristics + domain-similarity detector.
Defensive: tolerates missing snapshot, failed HTTP fetches,
and always returns a findings list (no unhandled exceptions).
"""

def run(target, opts, snap):
    from utils import safe_get
    findings = []
    score = 0
    reasons = []

    # safe extraction of snapshot url/body
    snapshot = (snap or {}).get('snapshot') if isinstance(snap, dict) else None
    url = ''
    body = ''

    try:
        if snapshot:
            url = snapshot.get('url') or ''
            body = snapshot.get('body') or ''
    except Exception:
        url = ''
        body = ''

    # if snapshot not provided or empty body, try a safe GET as fallback
    if not body:
        try:
            # small timeout and single retry - safe-mode
            r = safe_get(url or target, timeout=8, retries=0, delay=0.3)
            if r.get('ok'):
                body = r.get('text', '') or ''
                url = r.get('url') or (url or target)
                reasons.append('Fetched body as fallback')
            else:
                reasons.append(f'Fallback fetch failed: {r.get("error")}')
        except Exception as e:
            reasons.append(f'Exception during fallback fetch: {e}')

    # Basic checks
    if not url:
        url = target

    try:
        if not str(url).lower().startswith('https://'):
            score += 30
            reasons.append('No HTTPS (page URL not https)')
    except Exception:
        # defensive: if url is weird type
        reasons.append('URL check failed')

    # Parse and analyze safely
    try:
        import re, difflib
        domain = ''
        try:
            import tldextract
            domain = tldextract.extract(url).registered_domain or ''
        except Exception:
            domain = ''
            reasons.append('tldextract not available; domain-similarity weaker')

        # forms posting externally
        forms = re.findall(r'<form[\\s\\S]*?</form>', body, flags=re.I)
        for form in forms:
            action_m = re.search(r'action=[\\"\\\']([^\\\\"\\\']+)[\\"\\\']', form, flags=re.I)
            action = action_m.group(1) if action_m else ''
            if action:
                if action.startswith('http') and domain:
                    if domain not in action:
                        score += 40
                        reasons.append(f'Form posts to external domain ({action})')
                if action.startswith('/') and not url.lower().startswith('https://'):
                    score += 10
                    reasons.append('Form action relative + page not HTTPS')

        # check links for lookalike domains
        links = re.findall(r'href=[\\"\\\']([^\\\\"\\\']+)[\\"\\\']', body, flags=re.I)
        for link in links:
            if link.startswith('http') and domain:
                other = ''
                try:
                    import tldextract as _te
                    other = _te.extract(link).registered_domain or ''
                except Exception:
                    from urllib.parse import urlparse
                    other = urlparse(link).hostname or ''
                if other and other != domain:
                    ratio = difflib.SequenceMatcher(None, domain, other).ratio()
                    if ratio > 0.72:
                        score += 25
                        reasons.append(f'Lookalike domain: {other} (ratio={ratio:.2f})')

    except Exception as e:
        reasons.append(f'Parsing error: {e}')

    # keyword weighting (sensible weights)
    try:
        body_l = (body or '').lower()
        kw_score = {
            'verify': 4, 'confirm': 4, 'secure': 3, 'account': 2,
            'bank': 6, 'password': 6, 'login': 3, 'credential': 4
        }
        for k, v in kw_score.items():
            if k in body_l:
                score += v
                reasons.append(f'Keyword: {k}')
    except Exception:
        # ignore keyword analysis failures
        pass
# heuristic: many external resources (scripts/img) on a non-matching host -> suspicious
    try:
        import re
        hosts = set()
        for src in re.findall(r'(?:src|href)=[\\"\\\']([^\\\\"\\\']+)[\\"\\\']', body, flags=re.I):
            if src.startswith('http'):
                from urllib.parse import urlparse
                hosts.add(urlparse(src).hostname or '')
        if domain and hosts:
            ext_hosts = [h for h in hosts if h and domain not in h]
            if len(ext_hosts) >= 3:
                score += 10
                reasons.append('Multiple external resources on page')
    except Exception:
        pass

    # final severity
    severity = 'low' if score < 20 else ('medium' if score < 50 else 'high')
    findings.append({
        'severity': severity,
        'title': 'Phishing likelihood',
        'detail': f'score={score}',
        'recommendation': 'Review forms, external links and hosting; validate form actions and TLS.',
        'score': score,
        'reasons': reasons[:12]  # concise
    })

    return {'score': score, 'reasons': reasons, 'findings': findings}
