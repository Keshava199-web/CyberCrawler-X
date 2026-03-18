#!/usr/bin/env python3
"""
Secure Web Scraper - Hardened Version
Security protections included:
- SSRF protection
- DNS/IP validation
- Redirect validation
- Response size limits
- Streaming downloads
- Retry mechanism
- Path traversal protection
- Safe logging
"""

import requests
from requests.exceptions import RequestException
from bs4 import BeautifulSoup
import json
import argparse
import logging
import re
import socket
import ipaddress
import time
from urllib.parse import urlparse, urljoin
from pathlib import Path
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# -----------------------------
# Configuration
# -----------------------------

REQUEST_TIMEOUT = 10
MAX_RESPONSE_SIZE = 10 * 1024 * 1024
MAX_LINKS = 1000
USER_AGENT = "SecureScraper/1.0"

OUTPUT_DIR = Path("output")

# -----------------------------
# Logging
# -----------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)

# -----------------------------
# HTTP Session with Retry
# -----------------------------

session = requests.Session()

retry_strategy = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504]
)

adapter = HTTPAdapter(max_retries=retry_strategy)

session.mount("http://", adapter)
session.mount("https://", adapter)

session.headers.update({
    "User-Agent": USER_AGENT
})


# -----------------------------
# SSRF Protection
# -----------------------------

def is_private_ip(hostname):
    try:
        ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip)

        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_reserved
            or ip_obj.is_link_local
        ):
            return True

    except Exception:
        return True

    return False


def validate_url(url: str) -> str:

    if not url:
        raise ValueError("URL cannot be empty")

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP/HTTPS URLs allowed")

    if not parsed.hostname:
        raise ValueError("Invalid hostname")

    if is_private_ip(parsed.hostname):
        raise ValueError("Access to private/internal IPs denied")

    return url


# -----------------------------
# Download Response Safely
# -----------------------------

def fetch_content(url):

    logger.info("Fetching: %s", url)

    response = session.get(
        url,
        stream=True,
        timeout=REQUEST_TIMEOUT,
        allow_redirects=True,
        verify=True
    )

    response.raise_for_status()

    final_url = response.url
    parsed = urlparse(final_url)

    if is_private_ip(parsed.hostname):
        raise RequestException("Redirected to private/internal IP")

    size = 0
    content = b""

    for chunk in response.iter_content(1024):

        size += len(chunk)

        if size > MAX_RESPONSE_SIZE:
            raise RequestException("Response too large")

        content += chunk

    return content, response.headers


# -----------------------------
# Extract Links
# -----------------------------

def extract_links(html, base_url):

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

                results.append({
                    "text": text,
                    "link": absolute
                })

                seen.add(absolute)

        except Exception:
            continue

    logger.info("Extracted %s links", len(results))

    return results


# -----------------------------
# Extract Security Headers
# -----------------------------

def extract_security_headers(headers):

    security = {
        "Content-Security-Policy": headers.get("Content-Security-Policy"),
        "Strict-Transport-Security": headers.get("Strict-Transport-Security"),
        "X-Frame-Options": headers.get("X-Frame-Options"),
        "X-Content-Type-Options": headers.get("X-Content-Type-Options")
    }

    return security


# -----------------------------
# Save Results
# -----------------------------

def save_results(data, filename):

    OUTPUT_DIR.mkdir(exist_ok=True)

    safe_name = Path(filename).name
    output_path = OUTPUT_DIR / safe_name

    with open(output_path, "w", encoding="utf-8") as f:

        json.dump(data, f, indent=4)

    logger.info("Saved results to %s", output_path)


# -----------------------------
# Main
# -----------------------------

def main():

    parser = argparse.ArgumentParser(description="Secure Web Scraper")

    parser.add_argument(
        "--url",
        required=True,
        help="Target URL"
    )

    parser.add_argument(
        "--output",
        default="results.json",
        help="Output JSON file"
    )

    args = parser.parse_args()

    try:

        url = validate_url(args.url)

        html, headers = fetch_content(url)

        links = extract_links(html, url)

        security_headers = extract_security_headers(headers)

        result = {
            "target": url,
            "links_found": len(links),
            "links": links,
            "security_headers": security_headers
        }

        save_results(result, args.output)

        print("\nScraping completed successfully")
        print(f"Links found: {len(links)}")

        time.sleep(1)

    except Exception as e:

        logger.error("Error: %s", str(e))
        print("Error:", str(e))


if __name__ == "__main__":
    main()
