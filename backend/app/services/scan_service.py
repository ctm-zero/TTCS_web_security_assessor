import sys
import os
import asyncio
from typing import Dict, Any

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from app.scanners.header_scanner import fetch_headers
from app.rules.header_rules import (
    check_security_headers,
    check_server_information_disclosure,
)
from app.scanners.cookie_scanner import fetch_and_scan_cookies


async def run_full_scan(url: str) -> Dict[str, Any]:
    """Execute both header and cookie scans concurrently for a given URL
    and aggregate the findings and metadata.
    """
    # Fetch headers and cookies concurrently to optimize network latency
    header_task = fetch_headers(url)
    cookie_task = fetch_and_scan_cookies(url)

    (response, normalized_headers, header_meta), (cookies, cookie_meta) = (
        await asyncio.gather(header_task, cookie_task)
    )

    # Evaluate security rules and server disclosure on response headers
    security_header_findings = {}
    disclosure_findings = {}

    if normalized_headers:
        security_header_findings = check_security_headers(
            normalized_headers, header_meta
        )
        disclosure_findings = check_server_information_disclosure(normalized_headers)

    # report json structure
    scan_report = {
        "target_url": url,
        "metadata": {
            "status_code": header_meta.get("status_code"),
            "final_url": header_meta.get("final_url"),
            "is_https": header_meta.get("is_https"),
        },
        "headers": {
            "raw_count": len(normalized_headers),
            "security_findings": security_header_findings,
            "disclosure_findings": disclosure_findings,
        },
        "cookies": {"count": len(cookies), "items": cookies, "meta": cookie_meta},
    }

    return scan_report


if __name__ == "__main__":

    async def run_manual_test():
        test_url = "https://facebook.com"
        print(f"Running scan for: {test_url}\n")

        report = await run_full_scan(test_url)

        print("1. Target Metadata:")
        for k, v in report["metadata"].items():
            print(f"   - {k}: {v}")

        print(
            f"\n2. Header Security Findings ({len(report['headers']['security_findings'])}):"
        )
        for idx, (header, res) in enumerate(
            report["headers"]["security_findings"].items(), 1
        ):
            print(
                f"   {idx}. {header}: status={res['status']} | reason={res['reason']}"
            )

        print(
            f"\n3. Server Information Disclosure ({len(report['headers']['disclosure_findings'])}):"
        )
        for idx, (finding, res) in enumerate(
            report["headers"]["disclosure_findings"].items(), 1
        ):
            print(f"   {idx}. {finding}: status={res['status']} | value={res['value']}")

        print(f"\n4. Cookies Found ({report['cookies']['count']}):")
        if report["cookies"]["items"]:
            for idx, cookie in enumerate(report["cookies"]["items"], 1):
                print(f"   {idx}. {cookie['name']} = {cookie['value']}")
                print(
                    f"      httponly: {cookie['httponly']} | secure: {cookie['secure']} | samesite: {cookie['samesite']}"
                )
        else:
            print("   No cookies retrieved.")

    asyncio.run(run_manual_test())
