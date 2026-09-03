import sys
import os
import asyncio
import json
from typing import Dict, Any

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from app.scanners.header_scanner import fetch_headers
from app.rules.header_rules import (
    check_security_headers,
    check_server_information_disclosure,
)
from app.scanners.cookie_scanner import fetch_and_scan_cookies
from app.rules.cookie_rules import check_cookie_attributes
from app.scanners.tls_scanner import fetch_tls
from app.rules.tls_rules import check_tls_attributes


async def scan_url(url: str) -> Dict[str, Any]:
    """Perform security scan on the given URL with a highly optimized, non-repetitive JSON structure."""

    # 1. Scan Headers
    response, headers, header_meta = await fetch_headers(url)
    header_findings = check_security_headers(headers, header_meta)
    server_info_findings = check_server_information_disclosure(headers)
    all_headers = {**header_findings, **server_info_findings}

    # 2. Scan Cookies
    cookies, cookie_meta = await fetch_and_scan_cookies(url)
    cookie_findings = []
    for cookie in cookies:
        c_name = cookie.get("name", "Unnamed_Cookie")
        attributes_evaluation = check_cookie_attributes(cookie)
        cookie_findings.append(
            {"cookie_name": c_name, "attributes": attributes_evaluation}
        )

    # 3. Scan TLS
    tls_data, tls_meta = await fetch_tls(url)
    tls_findings = check_tls_attributes(tls_data)

    # 4. Group all meta information
    global_meta = {
        "target_url": url,
        "final_url": header_meta.get("final_url"),
        "status_code": header_meta.get("status_code"),
        "is_https": header_meta.get("is_https"),
        "cookie_count": cookie_meta.get("raw_count"),
        "tls_hostname": tls_meta.get("hostname"),
        "tls_port": tls_meta.get("port"),
        "tls_error": tls_meta.get("error"),
    }

    # 5. Structure the final results into clean groups
    results: Dict[str, Any] = {
        "meta": global_meta,
        "headers": {**header_findings, **server_info_findings},
        "cookies": cookie_findings,
        "tls": tls_findings,
    }

    return results


if __name__ == "__main__":

    async def run_manual_test():
        test_url = "https://facebook.com"
        print(f"Running manual scan for: {test_url}\n")

        scan_results = await scan_url(test_url)

        print("Scan Results:")
        print(json.dumps(scan_results, indent=4))

    asyncio.run(run_manual_test())
