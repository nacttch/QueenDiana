import time, socket, ssl, logging
from urllib.parse import urlparse, urljoin
try:
    import requests
except Exception:
    requests = None

logger = logging.getLogger("queen_diana")
if not logger.handlers:
    h = logging.FileHandler("queen_diana.log")
    h.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s"))
    logger.addHandler(h)
logger.setLevel(logging.INFO)

ANSI = {'reset':'\033[0m','green':'\033[32m','yellow':'\033[33m','red':'\033[31m','cyan':'\033[36m','bold':'\033[1m'}
def color(s,c): return f"{ANSI.get(c,'')}{s}{ANSI['reset']}"

def norm_url(u):
    u = u.strip()
    if not u.startswith('http://') and not u.startswith('https://'):
        u = 'https://' + u
    return u.rstrip('/')

_session = None
def get_session():
    global _session
    if _session is None and requests:
        _session = requests.Session()
        _session.headers.update({'User-Agent':'QueenDianaPro100X/1.0'})
        adapter = requests.adapters.HTTPAdapter(pool_connections=30, pool_maxsize=60, max_retries=1)
        _session.mount('http://', adapter); _session.mount('https://', adapter)
    return _session

def safe_get(url, timeout=10, retries=1, delay=0.5, allow_redirects=True, headers=None):
    headers = headers or {'User-Agent':'QueenDianaPro100X/1.0'}
    session = get_session()
    last_err = None
    if session is None:
        from urllib.request import Request, urlopen
        req = Request(url, headers=headers)
        for i in range(retries+1):
            try:
                with urlopen(req, timeout=timeout) as r:
                    data = r.read()
                    time.sleep(delay)
                    return {'ok': True, 'status': r.getcode(), 'text': data.decode('utf-8',errors='ignore'), 'headers': dict(r.getheaders()), 'url': r.geturl()}
            except Exception as e:
                last_err = str(e); logger.debug(f"urllib error: {e}"); time.sleep(delay)
        return {'ok': False, 'error': last_err}
    else:
        for i in range(retries+1):
            try:
                r = session.get(url, timeout=timeout, allow_redirects=allow_redirects, headers=headers)
                time.sleep(delay)
                return {'ok': True, 'status': r.status_code, 'text': r.text, 'headers': dict(r.headers), 'url': r.url}
            except Exception as e:
                last_err = str(e); logger.debug(f"requests error: {e}"); time.sleep(delay)
        return {'ok': False, 'error': last_err}

def resolve_hostname(host):
    try:
        if host.startswith('http'):
            host = urlparse(host).hostname
        infos = socket.getaddrinfo(host, None)
        ips = sorted(set([i[4][0] for i in infos]))
        return ips
    except Exception:
        return []

def get_cert(host, timeout=6):
    try:
        parsed = urlparse(host)
        h = parsed.hostname or host
        p = parsed.port or 443
        ctx = ssl.create_default_context()
        with socket.create_connection((h,p), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=h) as ssock:
                return ssock.getpeercert()
    except Exception as e:
        return {'error': str(e)}

def url_join(base, path):
    return urljoin(base, path)
