<div align="center">
  
![QueenDiana Banner](https://img.shields.io/badge/QueenDiana-Pro_Max-ff69b4.svg)
![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

# QueenDiana

<img src="https://github.com/nacttch/QueenDiana/blob/main/QueenDiana.png" alt="QueenDiana" width="350" height="350" style="border-radius: 50%;" />

</div>

## Overview

QueenDiana is a compact, professional command-line reconnaissance toolkit focused on non-intrusive information gathering and passive analysis. It collects site headers and TLS details, scans for sensitive paths, analyzes credential/login pages, performs phishing and domain-similarity checks, inspects CSP and other security headers, crawls sitemaps, and fingerprints CMS/WAFs. Results are saved as structured JSON reports.

**Disclaimer:** Use QueenDiana only on domains and networks for which you have explicit written permission. Unauthorized scanning or probing of systems you do not own is illegal.

---

## Features

* **HTTP Snapshot:** Fetch headers, status code, and TLS certificate info.
* **Sensitive Paths Scan:** Wordlist-driven checks for common admin/backdoor files.
* **Credential/Login Analysis:** Locate login forms and inspect form attributes.
* **Phishing / Domain Similarity:** URL similarity and basic phishing indicators.
* **CSP & Security Headers:** Detect missing/weak CSP and other security headers.
* **Sitemap Crawl:** Crawl and extract internal links (limited depth).
* **Passive XSS/SQLi Indicators:** Detect patterns that may indicate vulnerabilities (no exploitation).
* **CMS & WAF Detection:** Fingerprint common CMSs and WAFs.
* **Reports:** JSON output saved per run with timestamp.

---

## Quick CLI Preview

```
Target (example.com or https://example.com): example.com

1) Quick Snapshot (headers, TLS)
2) Sensitive paths scan
3) Credential/login analysis
4) Phishing + domain similarity
5) CSP analysis & security headers
6) Sitemap crawl
7) Passive XSS/SQLi indicators (non-exploit)
8) CMS & WAF detection
9) Run Full Audit
0) Exit
Choice:
```

---

## Installation

1. Clone the repo:

```bash
git clone https://github.com/<your-user>/QueenDiana.git
cd QueenDiana
```

2. Create & activate a virtual environment (recommended):

```bash
python3 -m venv venv
# macOS / Linux
source venv/bin/activate

# Windows (PowerShell)
venv\Scripts\Activate.ps1
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

If `requirements.txt` is not present, typical dependencies include:

```
requests
beautifulsoup4
tldextract
lxml
python-whois
tqdm
```

Adjust according to your `engine.py` needs.

---

## Usage

Run the interactive CLI:

```bash
python3 queen_diana.py
```

Steps:

1. Enter the target domain or URL (e.g. `example.com` or `https://example.com`).
2. Choose a module from the menu, or select `9` to run a full passive audit.
3. Reports will be saved to the `report/` directory as `queen_diana_YYYYMMDD_HHMMSS.json`.

Example non-interactive invocation (if you add CLI flags):

```bash
python3 queen_diana.py --target https://example.com --mode http
```

---

## Report Output

Reports are written to `report/` and include a timestamp.

* `report.json` — structured JSON containing module results, headers, discovered paths, and notes.

---

## Available Modules

* `http` — Quick snapshot (headers, TLS, status)
* `sensitive` — Sensitive path discovery (wordlist)
* `cred` — Login/credential page analysis
* `phish` — Phishing indicators & domain-similarity checks
* `csp` — CSP and security headers analysis
* `sitemap` — Sitemap crawl and URL extraction
* `indicators` — Passive XSS/SQLi indicators (no exploits)
* `cms` — CMS & WAF detection
* `full` — Run a collection of passive modules

---

## Customization

* `config.py` — central settings (timeouts, retries, user-agent, output directory).
* `wordlists/` — add custom wordlists for `sensitive` scans.
* `engine.py` — implement or tweak module behavior and detection heuristics.
* `report/` — change output location or post-process reports into HTML.

Tip: keep reasonable `delay` and `retries` settings in `opts` to avoid overloading targets.

---

## Legal / Disclaimer

This tool is intended for:

* ✅ Educational purposes
* ✅ Authorized security testing
* ✅ Security research and responsible disclosure

⚠️ Always obtain written authorization before testing systems you do not own. The author(s) are not responsible for misuse.

---

## Contributing

We welcome contributions:

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Make changes & add tests if applicable
4. Submit a pull request with clear notes

---

## Star & Support

If you find QueenDiana useful, please star the project on GitHub ⭐ — it helps us grow and improve.

---

## License

MIT License — see the `LICENSE` file for details.
