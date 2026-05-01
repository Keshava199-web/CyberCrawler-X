#!/usr/bin/env python3
"""
Secure Web Scraper - Hardened Version
Security protections included:
- SSRF protection (on both main fetch AND all link checks)
- DNS/IP validation
- Redirect validation (on both main fetch AND all link checks)
- Response size limits
- Streaming downloads
- Retry mechanism with per-request delay
- Path traversal protection
- Content-Type validation before HTML parsing
- Safe logging
"""

import re
import requests
from requests.exceptions import RequestException
from bs4 import BeautifulSoup
import json
import argparse
import logging
import socket
import ipaddress
import time
from pathlib import Path
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle, Spacer
from urllib.parse import urlparse, urlunparse, urljoin
from datetime import datetime
import random
from reportlab.platypus import Image

def redact_url(url):
    p = urlparse(url)
    return urlunparse(p._replace(query="[redacted]"))
# ─────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────

REQUEST_TIMEOUT = 10          # seconds — used everywhere
LINK_CHECK_TIMEOUT = 5        # shorter timeout for bulk link checks
LINK_CHECK_DELAY = 0.2        # seconds between link requests (polite crawling)
MAX_RESPONSE_SIZE = 10 * 1024 * 1024  # 10 MB
MAX_LINKS = 1000
USER_AGENT = "SecureScraper/1.0"

OUTPUT_DIR = Path("output")

# ─────────────────────────────────────────
# Logging
# ─────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────
# HTTP Session factory
# ─────────────────────────────────────────

def build_session() -> requests.Session:
    """
    Create a fresh requests.Session with retry logic.
    Called inside main() so the session is never a global mutable.
    """
    session = requests.Session()

    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504]
    )

    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": USER_AGENT})

    return session


# ─────────────────────────────────────────
# SSRF Protection
# ─────────────────────────────────────────

def is_private_ip(hostname: str) -> bool:
    """
    Return True if the hostname resolves to a private, loopback,
    link-local, or reserved IP — any address that should not be
    reachable from an external scraper.
    On resolution failure, default to True (block it).
    """
    try:
        ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip)

        return (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_reserved
            or ip_obj.is_link_local
        )

    except Exception:
        return True  # block on resolution failure


def validate_url(url: str) -> str:
    """
    Raise ValueError if the URL is empty, uses a non-HTTP scheme,
    has no hostname, or resolves to a private/internal IP.
    Returns the original URL string if all checks pass.
    """
    if not url:
        raise ValueError("URL cannot be empty")

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Only HTTP/HTTPS URLs allowed, got: {parsed.scheme!r}")

    if not parsed.hostname:
        raise ValueError("Invalid hostname")

    if is_private_ip(parsed.hostname):
        raise ValueError(f"Access to private/internal IPs denied: {parsed.hostname}")

    return url


def _assert_no_ssrf_redirect(response: requests.Response) -> None:
    """
    After a request that followed redirects, check that the final
    destination URL did not land on a private/internal IP.
    Raises RequestException if it did.
    """
    final_url = response.url
    parsed = urlparse(final_url)

    if parsed.hostname and is_private_ip(parsed.hostname):
        raise RequestException(
            f"Redirected to private/internal IP: {parsed.hostname}"
        )


# ─────────────────────────────────────────
# Download Response Safely
# ─────────────────────────────────────────

def fetch_content(url: str, session: requests.Session) -> tuple[bytes, requests.structures.CaseInsensitiveDict]:
    """
    Fetch a URL, streaming the response to enforce the MAX_RESPONSE_SIZE
    cap.  Validates the final URL after redirects against private IPs.
    Also validates Content-Type is HTML before returning.

    Returns (body_bytes, response_headers).
    """
    # logger.info("Fetching: %s", url)
    logger.info("Fetching: %s", redact_url(url))
    response = session.get(
        url,
        stream=True,
        timeout=REQUEST_TIMEOUT,
        allow_redirects=True,
        verify=True
    )

    response.raise_for_status()

    # ── SSRF redirect check ──────────────────────────────────────────
    _assert_no_ssrf_redirect(response)

    # ── Content-Type guard ───────────────────────────────────────────
    content_type = response.headers.get("Content-Type", "")
    if "text/html" not in content_type:
        raise ValueError(
            f"Expected text/html, got Content-Type: {content_type!r}"
        )

    # ── Size-limited streaming read ──────────────────────────────────
    size = 0
    content = b""

    for chunk in response.iter_content(1024):
        size += len(chunk)

        if size > MAX_RESPONSE_SIZE:
            raise RequestException("Response too large — aborting download")

        content += chunk

    return content, response.headers


# ─────────────────────────────────────────
# Extract Links
# ─────────────────────────────────────────

def extract_links(html: bytes, base_url: str) -> list[dict]:
    """
    Parse HTML and return a deduplicated list of absolute links,
    each as {"text": ..., "link": ...}.
    Skips javascript:, mailto:, tel:, and data: hrefs.
    """
    soup = BeautifulSoup(html, "lxml")

    results = []
    seen = set()

    for link in soup.find_all("a", limit=MAX_LINKS):
        text = link.get_text(strip=True)[:200]
        href = link.get("href")

        if not text or not href:
            continue

        if href.startswith(("javascript:", "mailto:", "tel:", "data:")):
            continue

        try:
            absolute = urljoin(base_url, href)

            if absolute not in seen:
                results.append({"text": text, "link": absolute})
                seen.add(absolute)

        except Exception:
            continue

    logger.info("Extracted %d links", len(results))
    return results

# JS - File Analysis:
def extract_js_files(html: bytes, base_url: str):
    soup = BeautifulSoup(html, "lxml")
    scripts = []

    for script in soup.find_all("script", src=True):
        try:
            js_url = urljoin(base_url, script["src"])
            scripts.append(js_url)
        except:
            continue

    return scripts

# ─────────────────────────────────────────
# Link Status Checker
# ─────────────────────────────────────────

def check_link_statuses(links: list[dict], session: requests.Session) -> tuple[list[dict], dict]:
    """
    HEAD (falling back to GET) every link and record its HTTP status.

    Security: each URL is validated against private IPs before requesting,
    and each response's final URL is checked for SSRF-via-redirect.

    Returns (annotated_links, summary_counts).
    """
    summary = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "error": 0, "blocked": 0}
    results = []

    for entry in links:
        url = entry["link"]

        # ── Pre-request SSRF check ───────────────────────────────────
        parsed_hostname = urlparse(url).hostname
        if not parsed_hostname or is_private_ip(parsed_hostname):
            logger.warning("Blocked SSRF candidate: %s", url)
            summary["blocked"] += 1
            results.append({**entry, "status": "blocked"})
            time.sleep(LINK_CHECK_DELAY)
            continue

        # ── Polite delay between requests ────────────────────────────
        time.sleep(LINK_CHECK_DELAY)

        try:
            response = session.head(
                url,
                timeout=LINK_CHECK_TIMEOUT,
                allow_redirects=True
            )

            # Some servers don't support HEAD — fall back to GET
            if response.status_code >= 400:
                response = session.get(
                    url,
                    timeout=LINK_CHECK_TIMEOUT,
                    allow_redirects=True
                )

            # ── Post-redirect SSRF check ─────────────────────────────
            _assert_no_ssrf_redirect(response)

            status_code = response.status_code

            if 200 <= status_code < 300:
                summary["2xx"] += 1
            elif 300 <= status_code < 400:
                summary["3xx"] += 1
            elif 400 <= status_code < 500:
                summary["4xx"] += 1
            elif 500 <= status_code < 600:
                summary["5xx"] += 1

            results.append({**entry, "status": status_code})

        except Exception as exc:
            logger.debug("Error checking %s: %s", url, exc)
            summary["error"] += 1
            results.append({**entry, "status": "error"})

    return results, summary


# ─────────────────────────────────────────
# Security Headers Extractor
# ─────────────────────────────────────────

def extract_security_headers(headers: requests.structures.CaseInsensitiveDict) -> dict:
    """
    Pull the four most important security-related response headers.
    Values are None when the header is absent.
    """
    return {
        "Content-Security-Policy":   headers.get("Content-Security-Policy"),
        "Strict-Transport-Security": headers.get("Strict-Transport-Security"),
        "X-Frame-Options":           headers.get("X-Frame-Options"),
        "X-Content-Type-Options":    headers.get("X-Content-Type-Options"),
    }

# sens--data
def detect_sensitive_data(content: str):
    PATTERNS = {
        "emails": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "aws_keys": r"AKIA[0-9A-Z]{16}",
        "jwt": r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
        "api_keys": r"(api[_-]?key\s*=\s*[A-Za-z0-9\-_]{16,})"
    }

    findings = {}

    for name, pattern in PATTERNS.items():
        matches = re.findall(pattern, content)
        if matches:
            findings[name] = list(set(matches))

    return findings
# ─────────────────────────────────────────
# Save Results
# ─────────────────────────────────────────

def save_results(data: dict, filename: str) -> None:
    """
    Write JSON output to OUTPUT_DIR/<filename>.
    Uses Path.name to strip any directory traversal from filename.
    """
    OUTPUT_DIR.mkdir(exist_ok=True)

    safe_name = Path(filename).name          # strip any path traversal
    output_path = OUTPUT_DIR / safe_name

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

    logger.info("Saved results to %s", output_path)

from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle, Spacer
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

def get_risk(status):
    if status == "blocked":
        return "MEDIUM"
    if isinstance(status, int):
        if status >= 500:
            return "HIGH"
        elif status >= 400:
            return "MEDIUM"
        else:
            return "LOW"
    return "LOW"

def risk_priority(status):
    if status == "blocked":
        return 2
    if isinstance(status, int):
        if status >= 500:
            return 3
        elif status >= 400:
            return 2
        elif status >= 300:
            return 1
    return 0
# for pdf format;
def save_pdf(data, filename):
    OUTPUT_DIR.mkdir(exist_ok=True)

    output_path = OUTPUT_DIR / Path(filename).name

    doc = SimpleDocTemplate(str(output_path))
    styles = getSampleStyleSheet()
    report_id = f"CCX-{datetime.now().strftime('%Y%m%d')}-{random.randint(1000, 9999)}"
    generated_time = datetime.now().strftime("%Y-%m-%d %H:%M")
    author = "SK34Ry"

    content = []

    def add_footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 9)
        canvas.drawString(30, 20, "Generated by CyberCrawler-X | Keshava")
        canvas.restoreState()

    # 🔥 Executive Summary
    # content.append(Paragraph("CyberCrawler-X Security Report", styles["Title"]))
    # content.append(Spacer(1, 10))
    content.append(Paragraph("<b>CyberCrawler-X Security Report</b>", styles["Title"]))
    content.append(Spacer(1, 8))

    content.append(Paragraph(f"<b>Report ID:</b> {report_id}", styles["Normal"]))
    content.append(Paragraph(f"<b>Generated:</b> {generated_time}", styles["Normal"]))
    content.append(Paragraph(f"<b>Author:</b> {author}", styles["Normal"]))

    content.append(Spacer(1, 15))

    content.append(Paragraph(f"Target: {data['target']}", styles["Normal"]))
    content.append(Paragraph(f"Total Links: {data['links_found']}", styles["Normal"]))
    content.append(Spacer(1, 10))

    # 🔥 Summary
    content.append(Paragraph("Summary", styles["Heading2"]))
    content.append(Paragraph(f"Generated On: {generated_time}", styles["Normal"]))
    for k, v in data["summary"].items():
        content.append(Paragraph(f"{k}: {v}", styles["Normal"]))

    content.append(Spacer(1, 10))

    content.append(Paragraph("Key Findings", styles["Heading2"]))

    if data["summary"]["5xx"] > 0:
        content.append(Paragraph("HIGH: Server errors detected (5xx)", styles["Normal"]))

    if data["summary"]["4xx"] > 0:
        content.append(Paragraph("MEDIUM: Broken links detected (4xx)", styles["Normal"]))

    if data["summary"]["blocked"] > 0:
        content.append(Paragraph("MEDIUM: Internal/blocked endpoints found", styles["Normal"]))

    content.append(Spacer(1, 10))

    #  Helper;
    def extract_domain(url):
        try:
            return urlparse(url).hostname
        except:
            return None



    # 🔥 Table Data
    table_data = [["S.No", "Title", "Link", "Status", "Risk"]]

    # for i, link in enumerate(data["links"][:30], start=1):  # limit for PDF size
    #     risk = get_risk(link["status"])

    sorted_links = sorted(
        data["links"],
        key=lambda x: risk_priority(x["status"]),
        reverse=True
    )

    for i, link in enumerate(sorted_links[:30], start=1):
        risk = get_risk(link["status"])

        table_data.append([
            str(i),
            link["text"][:30],
            link["link"][:50],
            str(link["status"]),
            risk
        ])

    table = Table(table_data)

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
    ]))

    content.append(Paragraph("Findings Table", styles["Heading2"]))
    content.append(table)

    # doc.build(content)
    doc.build(content, onFirstPage=add_footer, onLaterPages=add_footer)
    print(f"PDF saved at {output_path}")

def classify_domains(links, base_url):
    main_domain = urlparse(base_url).hostname
    external = []

    for link in links:
        domain = urlparse(link["link"]).hostname
        if domain and domain != main_domain:
            external.append(domain)

    return list(set(external))

def extract_links_playwright(url: str) -> list[dict]:
    from playwright.sync_api import sync_playwright

    results = []
    seen = set()

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        # Load page and wait for JS to render
        page.goto(url, wait_until="networkidle", timeout=20000)

        anchors = page.query_selector_all("a[href]")

        for a in anchors:
            href = a.get_attribute("href")
            text = (a.inner_text() or "").strip()[:200]

            if not href:
                continue

            absolute = page.url if href.startswith("#") else href

            if absolute not in seen:
                results.append({"text": text or "(no text)", "link": absolute})
                seen.add(absolute)

        browser.close()

    return results
# ─────────────────────────────────────────
# Main
# ─────────────────────────────────────────

def main() -> dict | None:
    parser = argparse.ArgumentParser(description="Secure Web Scraper")

    parser.add_argument("--url",    required=True,          help="Target URL to scrape")
    parser.add_argument("--output", default="results.json", help="Output JSON filename")

    args = parser.parse_args()

    session = build_session()

    try:
        url = validate_url(args.url)

        html, headers = fetch_content(url, session)

        text_content = html.decode(errors="ignore")
        sensitive_data = detect_sensitive_data(text_content)

        links = extract_links(html, url)

        # 🔥 JS + recon steps
        js_files = extract_js_files(html, url)
        js_findings = scan_js_files(js_files, session)

        # 🔥 Playwright fallback (ONLY if no links found)
        if len(links) == 0:
            logger.warning("No links found — trying browser rendering (Playwright)")
            try:
                links = extract_links_playwright(url)
                logger.info("Extracted %d links via Playwright", len(links))
            except Exception as e:
                logger.error(f"Playwright failed: {e}")

        # 🔥 Endpoint + domain analysis
        endpoints = extract_endpoints(text_content)
        external_domains = classify_domains(links, url)

        # 🔥 API endpoint capture (optional but powerful)
        try:
            api_endpoints = capture_api_endpoints(url)
        except Exception as e:
            logger.debug(f"API capture failed: {e}")
            api_endpoints = []

        logger.info("Checking link statuses for %d links...", len(links))
        links, summary = check_link_statuses(links, session)

        security_headers = extract_security_headers(headers)

        # links = extract_links(html, url)
        #
        # # 🔥 JS + recon steps (must be here)
        # js_files = extract_js_files(html, url)
        # js_findings = scan_js_files(js_files, session)
        #
        #
        # endpoints = extract_endpoints(text_content)
        # external_domains = classify_domains(links, url)
        #
        # logger.info("Checking link statuses for %d links...", len(links))
        # links, summary = check_link_statuses(links, session)
        #
        # security_headers = extract_security_headers(headers)

        result = {
            "target": url,
            "links_found": len(links),
            "summary": summary,
            "links": links,
            "security_headers": security_headers,
            "sensitive_data": sensitive_data,
            "js_sensitive_data": js_findings,
            "endpoints": endpoints,
            "external_domains": external_domains,
            "api_endpoints": api_endpoints,
        }

        # save_results(result, args.output)
        if args.output.endswith(".pdf"):
            save_pdf(result, args.output)
        else:
            save_results(result, args.output)

        print("\nScraping completed successfully")
        print(f"Links found : {len(links)}")
        print(f"Summary     : {summary}")

        return result

    except Exception as e:
        logger.error("Fatal error: %s", str(e))
        print("Error:", str(e))
        return None

# JS - Scanning fxn;
def scan_js_files(js_urls, session):
    findings = {}

    for url in js_urls:
        try:
            res = session.get(url, timeout=5)
            content = res.text

            detected = detect_sensitive_data(content)

            if detected:
                findings[url] = detected

        except:
            continue

    return findings

def extract_endpoints(content: str):
    pattern = r"/(api|v1|admin|auth|internal)[a-zA-Z0-9/_-]*"
    matches = re.finditer(pattern, content)
    return list(set(m.group(0) for m in matches))

if __name__ == "__main__":
    main()
