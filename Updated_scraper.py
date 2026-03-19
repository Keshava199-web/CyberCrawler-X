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

import requests
from requests.exceptions import RequestException
from bs4 import BeautifulSoup
import json
import argparse
import logging
import socket
import ipaddress
import time
from urllib.parse import urlparse, urljoin
from pathlib import Path
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

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
    logger.info("Fetching: %s", url)

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

        links = extract_links(html, url)

        logger.info("Checking link statuses for %d links...", len(links))
        links, summary = check_link_statuses(links, session)

        security_headers = extract_security_headers(headers)

        result = {
            "target": url,
            "links_found": len(links),
            "summary": summary,
            "links": links,
            "security_headers": security_headers,
        }

        save_results(result, args.output)

        print("\nScraping completed successfully")
        print(f"Links found : {len(links)}")
        print(f"Summary     : {summary}")

        return result

    except Exception as e:
        logger.error("Fatal error: %s", str(e))
        print("Error:", str(e))
        return None


if __name__ == "__main__":
    main()
