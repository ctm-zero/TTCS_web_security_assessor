from typing import Any

from backend.app.scanners.header_scanner import fetch_headers
from backend.app.rules.header_rules import (
    check_security_headers,
    check_server_information_disclosure,
)
from backend.app.scanners.cookie_scanner import fetch_and_scan_cookies
from backend.app.rules.cookie_rules import check_cookie_attributes
from backend.app.scanners.tls_scanner import fetch_tls
from backend.app.rules.tls_rules import check_tls_attributes
from backend.app.scoring.score_engine import score_results
from backend.app.remediation.generator import generate_remediation


async def scan_url(url: str) -> dict[str, Any]:
    """
    Perform a complete security assessment for a target URL.

    Flow:
        1. Collect HTTP headers
        2. Evaluate HTTP security headers
        3. Collect and evaluate cookies
        4. Collect and evaluate TLS information
        5. Combine scan results
        6. Calculate the final security score
        7. Return the complete report
    """

    # --------------------------------------------------
    # 1. HTTP Headers
    # --------------------------------------------------
    _, headers, header_meta = await fetch_headers(url)

    header_findings = check_security_headers(
        headers,
        header_meta,
    )

    server_info_findings = check_server_information_disclosure(headers)

    header_findings.update(server_info_findings)

    # --------------------------------------------------
    # 2. Cookies
    # --------------------------------------------------
    cookies, cookie_meta = await fetch_and_scan_cookies(url)

    cookie_findings = []

    for cookie in cookies:
        cookie_name = cookie.get(
            "name",
            "Unnamed_Cookie",
        )

        attributes = check_cookie_attributes(cookie)

        cookie_findings.append(
            {
                "cookie_name": cookie_name,
                "attributes": attributes,
            }
        )

    # --------------------------------------------------
    # 3. TLS
    # --------------------------------------------------
    tls_data, tls_meta = await fetch_tls(url)

    tls_findings = check_tls_attributes(tls_data)

    # --------------------------------------------------
    # 4. Combine scan results
    # --------------------------------------------------
    scan_results = {
        "meta": {
            "target_url": url,
            "final_url": header_meta.get("final_url"),
            "status_code": header_meta.get("status_code"),
            "is_https": header_meta.get("is_https"),
            "cookie_count": cookie_meta.get("raw_count"),
            "tls_hostname": tls_meta.get("hostname"),
            "tls_port": tls_meta.get("port"),
            "tls_error": tls_meta.get("error"),
        },
        "headers": header_findings,
        "cookies": cookie_findings,
        "tls": tls_findings,
    }

    # --------------------------------------------------
    # 5. Scoring & Remediation
    # --------------------------------------------------
    # Chấm điểm kết quả quét
    report = score_results(scan_results)
    
    # Tự động sinh hướng dẫn khắc phục dựa trên báo cáo điểm số
    remediation_data = generate_remediation(report)
    
    # Đính kèm mảng remediation vào báo cáo trả về cho Frontend
    report["remediation"] = remediation_data["remediation"]

    return report
