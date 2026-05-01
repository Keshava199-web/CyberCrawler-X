<div align="center">

<img src="Cyber_crawler.png" alt="CyberCrawler-X" width="120" />

# CyberCrawler-X

**Automated web reconnaissance & attack surface analysis for security researchers**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-orange?style=flat-square)](CONTRIBUTING.md)

[Features](#-features) · [Installation](#-installation) · [Usage](#-usage) · [Output](#-example-output) · [Disclaimer](#-disclaimer)

</div>

---

## What Is CyberCrawler-X?

CyberCrawler-X is a Python-based reconnaissance tool that automates the discovery phase of web security testing. Point it at a target and it crawls endpoints, detects sensitive data exposures, evaluates security headers, scans JavaScript files, and produces a structured report — giving you a clear picture of the attack surface before manual testing begins.

```
$ python updated_scrap.py --url https://example.com

Scraping completed successfully
Links found : 48
Summary     : {'2xx': 35, '3xx': 5, '4xx': 6, '5xx': 2, 'error': 0, 'blocked': 0}
```

---

## ✨ Features

### 🗺️ Attack Surface Mapping
- Extracts and deduplicates all `<a href>` links from a target page
- Converts relative URLs to absolute URLs automatically
- Handles up to **1,000 links per scan**
- Falls back to **Playwright browser rendering** if no links are found via static HTML parsing (handles JS-heavy SPAs)

### 🧩 JavaScript File Analysis
- Extracts all `<script src="...">` files loaded by the page
- Scans each JS file's source for sensitive data patterns (API keys, tokens, credentials)
- Reports findings per JS file URL

### 🔍 Endpoint Discovery
Scans page content with regex to surface high-interest paths:

| Path pattern | Why it matters |
|---|---|
| `/api`, `/v1` | API surface |
| `/auth` | Authentication flows |
| `/admin` | Admin panels |
| `/internal` | Internal tooling |

### 📡 HTTP Status Analysis

HEAD requests (with GET fallback) are made against every discovered link:

| Code | Classification |
|------|---------------|
| `2xx` | Accessible |
| `3xx` | Redirect |
| `4xx` | Client error / blocked |
| `5xx` | Server error |
| `blocked` | SSRF-blocked internal endpoint |

### 🚨 Risk Classification

| Risk | Trigger |
|------|---------|
| **HIGH** | Server errors (`5xx`) |
| **MEDIUM** | Broken endpoints (`4xx`) or SSRF-blocked links |
| **LOW** | Accessible endpoints (`2xx`/`3xx`) |

PDF reports sort findings by risk level (HIGH → LOW).

### 🔐 Built-in Security Guardrails
- **SSRF protection** — validates hostnames against private/loopback/reserved IP ranges before every request, including link checks and JS downloads
- **Redirect validation** — re-checks the final destination URL after any redirect chain
- **DNS/IP validation** — blocks on resolution failure
- **Response size cap** — streaming download aborts at 10 MB
- **Content-Type enforcement** — HTML parsing only proceeds on `text/html` responses
- **Query string redaction** — query params are stripped from log output
- **Path traversal protection** — output filenames are sanitised with `Path.name`

### 🕵️ Sensitive Data Detection

Scans both page HTML and downloaded JS files for exposed patterns:

| Pattern | Example |
|---------|---------|
| Email addresses | `user@example.com` |
| AWS access keys | `AKIA...` |
| JWT tokens | `eyJ...` |
| API keys | `api_key=abc123...` |

### 🌐 External Domain Identification
Compares each discovered link's hostname against the target domain and returns a deduplicated list of third-party domains — useful for mapping the external attack surface and third-party integrations.

### 🔎 Security Header Analysis
Checks the target's response headers for the presence of:
- `Content-Security-Policy`
- `Strict-Transport-Security`
- `X-Frame-Options`
- `X-Content-Type-Options`

Missing headers are reported as `null` in output.

### 📄 Structured Reporting

| Format | Details |
|--------|---------|
| **JSON** | Full structured output — links, statuses, headers, sensitive data, JS findings, endpoints, external domains |
| **PDF** | Executive summary, key findings callouts, risk-sorted findings table (top 30), report ID, timestamp, author branding |

---

## 📁 Project Structure

```
CyberCrawler-X/
├── updated_scrap.py   # Core tool
├── output/            # Generated reports (auto-created)
├── README.md
└── logo.png           # Optional — used in reports
```

---

## ⚙️ Installation

```bash
git clone https://github.com/yourusername/CyberCrawler-X.git
cd CyberCrawler-X
pip install -r requirements.txt
```

**Core dependencies:** `requests`, `beautifulsoup4`, `lxml`, `reportlab`

**Optional (JS-rendered pages):**
```bash
pip install playwright
playwright install chromium
```

Playwright is only invoked automatically when static parsing returns zero links.

---

## 🚀 Usage

**Basic scan — JSON output**
```bash
python updated_scrap.py --url https://example.com
```

**Custom JSON filename**
```bash
python updated_scrap.py --url https://example.com --output result.json
```

**Generate PDF report**
```bash
python updated_scrap.py --url https://example.com --output report.pdf
```

Output files are written to the `output/` directory.

---

## 📊 Example Output

**Console**
```
Scraping completed successfully
Links found : 48
Summary     : {'2xx': 35, '3xx': 5, '4xx': 6, '5xx': 2, 'error': 0, 'blocked': 0}
```

**JSON structure**
```json
{
  "target": "https://example.com",
  "links_found": 48,
  "summary": { "2xx": 35, "3xx": 5, "4xx": 6, "5xx": 2, "error": 0, "blocked": 0 },
  "links": [{ "text": "Login", "link": "https://example.com/auth", "status": 200 }],
  "security_headers": {
    "Content-Security-Policy": null,
    "Strict-Transport-Security": "max-age=31536000"
  },
  "sensitive_data": {},
  "js_sensitive_data": {},
  "endpoints": ["/api/v1/users", "/admin/dashboard"],
  "external_domains": ["cdn.example.net", "analytics.google.com"],
  "api_endpoints": []
}
```

---

## 🎯 Bug Bounty Workflow

```
1. Run CyberCrawler-X against your target scope
2. Review discovered endpoints, external domains, and security header gaps
3. Check sensitive_data and js_sensitive_data for immediate findings
4. Prioritize HIGH/MEDIUM risk links for manual follow-up
5. Manually validate and report confirmed vulnerabilities
```

> CyberCrawler-X automates reconnaissance. All findings require manual validation before reporting.

---

## ⚠️ Disclaimer

This tool is intended for **authorized security research, bug bounty programs, and educational use only**.

Do not use CyberCrawler-X against any system without explicit written permission. The author assumes no liability for unauthorized or malicious use.

---

## 🤝 Contributing

Contributions are welcome. Please:
1. Open an issue to discuss your proposed change
2. Fork the repo and create a feature branch
3. Submit a pull request with a clear description

---

## 📜 License

[MIT](LICENSE) — free to use, modify, and distribute with attribution.

---

<div align="center">

Built with Python · Designed for Security Researchers

</div>
