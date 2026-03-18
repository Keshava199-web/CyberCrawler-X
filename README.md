# 🕷️ CyberCrawler-X

> A secure, automated web scraping tool for link extraction, availability monitoring, security header analysis, and structured report generation.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

---

## 📖 Overview

**CyberCrawler-X** is a Python-based web scraping and security analysis tool designed for automation, monitoring, and secure network handling. It extracts links from any webpage, verifies their availability via HTTP status checks, analyzes security headers, detects indicators of compromise (IOCs), and exports structured reports in multiple formats.

Whether you're doing web reliability audits, security research, or reconnaissance, CyberCrawler-X gives you a complete picture of a target URL in one run.

---

## ✨ Features

### 🔗 Web Scraping
- Extracts all links from any webpage
- Automatically converts relative URLs to absolute URLs
- Deduplicates links to eliminate noise
- Supports large-scale extraction (up to 1,000 links)

### 📡 Link Monitoring
Performs automated HTTP status checks and categorizes each response:

| Code Range | Meaning         |
|------------|-----------------|
| `2xx`      | Success         |
| `3xx`      | Redirect        |
| `4xx`      | Client Error    |
| `5xx`      | Server Error    |

### 🔒 Security Features
- **SSRF Protection** — Blocks server-side request forgery attempts
- **DNS Rebinding Protection** — Guards against DNS rebinding attacks
- **Redirect Validation** — Verifies redirect chains for safety
- **Private Network Blocking** — Prevents access to internal/private IP ranges
- **Content-Type Validation** — Ensures responses match expected types
- **Response Size Limits** — Prevents memory exhaustion from oversized responses

### 🛡️ Security Header Analysis
Detects the presence (or absence) of the following HTTP security headers:

- `Content-Security-Policy`
- `Strict-Transport-Security`
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`

### 🧩 IOC Detection
Extracts potential **Indicators of Compromise (IOCs)** from page content, including:

- CVE identifiers (e.g., `CVE-2024-XXXXX`)
- IP addresses
- File hashes (MD5, SHA1, SHA256)

### 📄 Multiple Output Formats
Generate reports in any of the following formats:

| Format | Flag           |
|--------|----------------|
| JSON   | `--format json` (default) |
| TXT    | `--format txt` |
| PDF    | `--format pdf` |
| DOCX   | `--format docx` |

---

## 🏗️ Project Structure

```
CyberCrawler-X/
│
├── scraper.py          # Core scraping and analysis logic
├── requirements.txt    # Python dependencies
├── README.md           # Project documentation
└── output/             # Generated reports saved here
```

---

## ⚙️ Installation

**1. Clone the repository**
```bash
git clone https://github.com/yourusername/CyberCrawler-X.git
cd CyberCrawler-X
```

**2. Install dependencies**
```bash
pip install -r requirements.txt
```

### 📋 Requirements

- Python **3.8+**
- Required libraries:

```
requests
beautifulsoup4
lxml
reportlab
python-docx
urllib3
```

---

## ▶️ Usage

**Basic scraping (JSON output by default)**
```bash
python scraper.py --url https://example.com
```

**Specify a custom output filename**
```bash
python scraper.py --url https://example.com --output report
```

**Generate a PDF report**
```bash
python scraper.py --url https://example.com --format pdf
```

**Generate a DOCX report**
```bash
python scraper.py --url https://example.com --format docx
```

**Skip link status checking (faster execution)**
```bash
python scraper.py --url https://example.com --no-check
```

---

## 📊 Example Output

**Console summary**
```
Scraping completed
Links found : 48
Output file : output/results.json
Summary     : {'2xx': 35, '3xx': 5, '4xx': 6, '5xx': 2, 'error': 0}
```

**Example JSON result**
```json
{
  "target": "https://example.com",
  "links_found": 48,
  "summary": {
    "2xx": 35,
    "3xx": 5,
    "4xx": 6,
    "5xx": 2,
    "error": 0
  },
  "security_headers": {
    "Content-Security-Policy": "present",
    "Strict-Transport-Security": "present",
    "X-Frame-Options": "missing"
  },
  "iocs_detected": {
    "cve_ids": [],
    "ip_addresses": ["192.168.1.1"],
    "hashes": []
  }
}
```

---

## ⚠️ Disclaimer

This tool is intended for **authorized security research, web auditing, and educational purposes only**. Do not use CyberCrawler-X against websites or systems without explicit permission from the owner. The authors are not responsible for any misuse or damage caused by this tool.

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!  
Feel free to open an [issue](https://github.com/yourusername/CyberCrawler-X/issues) or submit a pull request.

---

<p align="center">Built with 🐍 Python • Designed for Security-Conscious Developers</p>
