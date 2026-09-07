import sys
import os
import asyncio
import json
from dataclasses import dataclass
from typing import Dict, Any

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from app.services.scan_service import scan_url


def score_results(scan_results: Dict[str, Any]) -> Dict[str, Any]:
    """Score the scan results based on predefined rules and return a structured scoring report."""

    # Initialize scoring report
    scoring_report: Dict[str, Any] = {
        "meta": scan_results.get("meta", {}),
        "scores": {
            "meta": 0,
            "headers": 0,
            "cookies": 0,
            "tls": 0,
        },
        "details": {
            "meta": {},
            "headers": {},
            "cookies": [],
            "tls": {},
        },
    }
    BASELINE = 100
    # Points for Meta
    NOT_HTTPS = -50

    # Points for Headers

    HSTS_PASS_PRELOADED = 2
    HSTS_PASS = 0
    HSTS_WARN = -7
    HSTS_FAIL = -15

    CSP_PASS_RESTRICTIVE = 3
    CSP_PASS = 0
    CSP_WARN = -10
    CSP_FAIL = -20

    XFO_PASS = 0
    XFO_WARN = -5
    XFO_FAIL = -15

    XCTO_PASS = 0
    XCTO_FAIL = -5

    REFERRER_PASS = 5
    REFERRER_MISSING = 0
    REFERRER_INVALID = -3

    OPTIONAL_BONUS = 5

    SERVER_DISCLOSE = -3
    X_POWERED_DISCLOSE = -3

    # String marker for bonus points in header
    HSTS_PRELOADED_MARKER = "HSTS set with adequate max-age and preloaded"
    CSP_RESTRICTIVE_MARKER = (
        "CSP present and default-src 'none' and form-action restricted"
    )

    # Points for Cookie
    SESSION_SECURE_FULL = 0  # Session cookie: HttpOnly + Secure + valid SameSite value
    SESSION_SECURE_PARTIAL = (
        -15
    )  # Session cookie: HttpOnly + Secure, missing/bad SameSite value
    SESSION_FAIL = -30  # Session cookie: missing HttpOnly or Secure
    PERSISTENT_SECURE_FULL = (
        0  # Persistent cookie: HttpOnly + Secure + valid SameSite value
    )
    PERSISTENT_SECURE_PARTIAL = (
        -7
    )  # Persistent cookie: HttpOnly + Secure, missing/bad SameSite value
    PERSISTENT_FAIL = -15  # Persistent cookie: missing HttpOnly or Secure

    # Points for TLS/SSL
    TLS_VERSION_FAIL = -40
    CIPHER_SUITE_WEAK = -30
    CIPHER_SUITE_MISSING = -20
    CERT_EXPIRED = -40
    CERT_WARN = -10
    CERT_SELF_SIGNED = -25
    CERT_PARSING_FAILED = -20

    # Score Meta
    is_https = bool(scoring_report["meta"].get("is_https"))
    meta_score = BASELINE
    if not is_https:
        meta_score += NOT_HTTPS
        status, reason = "fail", "Site is not served over HTTPS"
    else:
        status, reason = "pass", "Site is served under HTTPS"
    scoring_report["scores"]["meta"] = meta_score
    scoring_report["details"]["meta"] = {
        "https_enforced": {
            "present": True,
            "value": is_https,
            "status": status,
            "reason": reason,
        }
    }

    # Score Headers
    # Main headers
    header_findings = scan_results.get("headers", {})
    scoring_report["details"]["headers"] = header_findings
    header_score = 0

    hsts = header_findings.get("strict-transport-security", {})
    hsts_reason = hsts.get("reason", "")
    hsts_status = hsts.get("status")
    if hsts_status == "pass":
        is_preloaded = HSTS_PRELOADED_MARKER in hsts_reason
        header_score += HSTS_PASS_PRELOADED if is_preloaded else HSTS_PASS
    elif hsts_status == "warn":
        header_score += HSTS_WARN
    elif hsts_status == "not_applicable":
        header_score += 0
    else:
        header_score += HSTS_FAIL

    csp = header_findings.get("content-security-policy", {})
    csp_reason = csp.get("reason", "")
    csp_status = csp.get("status")
    if csp_status == "pass":
        is_restrictive = CSP_RESTRICTIVE_MARKER in csp_reason
        header_score += CSP_PASS_RESTRICTIVE if is_restrictive else CSP_PASS
    elif csp_status == "warn":
        header_score += CSP_WARN
    else:
        header_score += CSP_FAIL

    xfo_status = header_findings.get("x-frame-options", {}).get("status")
    if xfo_status == "pass":
        header_score += XFO_PASS
    elif xfo_status == "warn":
        header_score += XFO_WARN
    else:
        header_score += XFO_FAIL

    xcto_status = header_findings.get("x-content-type-options", {}).get("status")
    header_score += XCTO_PASS if xcto_status == "pass" else XCTO_FAIL

    rp_status = header_findings.get("referrer-policy", {}).get("status")
    if rp_status == "pass":
        header_score += REFERRER_PASS
    elif rp_status == "warn":
        header_score += REFERRER_MISSING
    else:
        header_score += REFERRER_INVALID

    # Check for optional header
    for optional_header in (
        "x-permitted-cross-domain-policies",
        "cross-origin-resource-policy",
        "cross-origin-embedder-policy",
        "cross-origin-opener-policy",
    ):
        if header_findings.get(optional_header, {}).get("status") == "pass":
            header_score += OPTIONAL_BONUS

    # Check for server infomation
    server = header_findings.get("server", {}).get("status")
    if server == "warn":
        header_score += SERVER_DISCLOSE

    x_powered_by = header_findings.get("x-powered-by", {}).get("status")
    if x_powered_by == "warn":
        header_score += X_POWERED_DISCLOSE

    scoring_report["scores"]["headers"] = header_score

    # Score Cookies
    cookie_findings = scan_results.get("cookies", [])
    scoring_report["details"]["cookies"] = cookie_findings
    worst_cookie_score = None
    worst_cookie_name = None
    worst_cookie_reason = None

    for items in cookie_findings:
        cookie_name = items.get("cookie_name", "Unnamed_Cookie")
        attributes = items.get("attributes", {})

        http_only = attributes.get("httponly", {})
        secure = attributes.get("secure", {})
        samesite = attributes.get("samesite", {})
        max_age = attributes.get("max_age", {})
        expires = attributes.get("expires", {})

        has_max_age = max_age.get("present", False)
        has_expires = expires.get("present", False)
        is_session_cookie = not (has_max_age or has_expires)

        has_http_only = http_only.get("status") == "pass"
        has_secure = secure.get("status") == "pass"
        samesite_status = samesite.get("status")

        if not has_http_only or not has_secure:
            missing = []
            if not has_http_only:
                missing.append(http_only.get("reason", "Missing HttpOnly"))
            if not has_secure:
                missing.append(secure.get("reason", "Missing Secure"))
            this_score = SESSION_FAIL if is_session_cookie else PERSISTENT_FAIL
            this_reason = "; ".join(missing)
        elif samesite_status == "pass":
            this_score = (
                SESSION_SECURE_FULL if is_session_cookie else PERSISTENT_SECURE_FULL
            )
            this_reason = "HttpOnly, Secure, and SameSite all correctly set"
        else:
            this_score = (
                SESSION_SECURE_PARTIAL
                if is_session_cookie
                else PERSISTENT_SECURE_PARTIAL
            )
            this_reason = samesite.get("reason", "SameSite missing or invalid")

        if worst_cookie_score is None or worst_cookie_score > this_score:
            worst_cookie_name = cookie_name
            worst_cookie_score = this_score
            worst_cookie_reason = this_reason

    cookie_score = worst_cookie_score if worst_cookie_score is not None else 0
    scoring_report["scores"]["cookies"] = cookie_score
    scoring_report["details"]["cookie_scoring"] = {
        "worst_cookie": (
            {"name": worst_cookie_name, "reason": worst_cookie_reason}
            if worst_cookie_name
            else None
        ),
    }

    # Score TLS
    tls_findings = scan_results.get("tls", {})
    scoring_report["details"]["tls"] = tls_findings
    tls_score = 0

    tls_version_status = tls_findings.get("tls_version", {}).get("status")
    if tls_version_status == "fail":
        tls_score += TLS_VERSION_FAIL

    cipher_status = tls_findings.get("cipher_suite", {}).get("status")
    if cipher_status == "fail":
        tls_score += CIPHER_SUITE_WEAK
    elif cipher_status == "warn":
        tls_score += CIPHER_SUITE_MISSING

    cert_parsing_status = tls_findings.get("certificate_parsing", {}).get("status")
    if cert_parsing_status == "fail":
        tls_score += CERT_PARSING_FAILED
    else:
        cert_validity_status = tls_findings.get("certificate_validity", {}).get(
            "status"
        )
        if cert_validity_status == "fail":
            tls_score += CERT_EXPIRED
        elif cert_validity_status == "warn":
            tls_score += CERT_WARN
        else:
            tls_score += 0
        cert_trust_status = tls_findings.get("certificate_trust", {}).get("status")
        if cert_trust_status == "fail":
            tls_score += CERT_SELF_SIGNED
    scoring_report["scores"]["tls"] = tls_score

    return scoring_report


"""
def grading(score_result:Dict[str,Any]) -> Dict[str,Any]:
    Take scoring report and calculate the final score of the website based on letter grading
"""

if __name__ == "__main__":
    # Example usage
    async def run_test():
        test_url = "https://github.com/"
        print(f"Scanning URL: {test_url}")

        scan_results = await scan_url(test_url)
        scoring_report = score_results(scan_results)
        print("Scoring Report:")
        print(json.dumps(scoring_report, indent=4))

    asyncio.run(run_test())