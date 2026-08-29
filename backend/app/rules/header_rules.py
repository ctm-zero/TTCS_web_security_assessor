from typing import Dict, Any
import re

def _parse_max_age(hvalue: str) -> int:
    m = re.search(r"max-age\s*=\s*(\d+)", hvalue, flags=re.IGNORECASE)
    if m:
        try:
            return int(m.group(1))
        except ValueError:
            return 0
    return 0


def check_security_headers(
    headers: Dict[str, str], meta: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Evaluate important security headers per OWASP Security Response Header Cheat Sheet.

    Args:
        headers: normalized headers (lowercased keys)
        meta: response metadata containing `is_https` (bool)

    Returns:
        mapping header -> result dict {present, value, status, reason}
    """
    results: Dict[str, Dict[str, Any]] = {}

    def add(name: str, present: bool, value: str = None, status: str = "warn", reason: str = ""):
        results[name] = {"present": present, "value": value, "status": status, "reason": reason}

    is_https = bool(meta.get("is_https"))

    # Strict-Transport-Security (HSTS)
    hsts = headers.get("strict-transport-security")
    if is_https:
        if hsts:
            max_age = _parse_max_age(hsts)
            if max_age >= 31536000:
                add("strict-transport-security", True, hsts, "pass", "HSTS set with adequate max-age")
            else:
                add("strict-transport-security", True, hsts, "warn", "HSTS max-age is low")
        else:
            add("strict-transport-security", False, None, "fail", "Missing HSTS on HTTPS response")
    else:
        add("strict-transport-security", bool(hsts), hsts, "warn", "HSTS only applies to HTTPS responses")

    # Content-Security-Policy
    csp = headers.get("content-security-policy")
    if csp:
        if "unsafe-inline" in csp or "unsafe-eval" in csp:
            add("content-security-policy", True, csp, "warn", "CSP contains unsafe directives")
        else:
            add("content-security-policy", True, csp, "pass", "CSP present")
    else:
        add("content-security-policy", False, None, "warn", "Missing CSP")

    # X-Frame-Options
    xfo = headers.get("x-frame-options")
    if xfo:
        if xfo.lower() in ("deny", "sameorigin"):
            add("x-frame-options", True, xfo, "pass", "X-Frame-Options set")
        else:
            add("x-frame-options", True, xfo, "warn", "X-Frame-Options value is uncommon")
    else:
        add("x-frame-options", False, None, "warn", "Missing X-Frame-Options (clickjacking protection)")

    # X-Content-Type-Options
    xcto = headers.get("x-content-type-options")
    if xcto and xcto.lower() == "nosniff":
        add("x-content-type-options", True, xcto, "pass", "nosniff set")
    else:
        add("x-content-type-options", bool(xcto), xcto, "warn", "Missing or incorrect X-Content-Type-Options")

    # Referrer-Policy
    rp = headers.get("referrer-policy")
    allowed_rp = {
        "no-referrer",
        "no-referrer-when-downgrade",
        "same-origin",
        "origin",
        "strict-origin",
        "origin-when-cross-origin",
        "unsafe-url",
        "strict-origin-when-cross-origin",
    }
    if rp:
        if rp.lower() in allowed_rp:
            add("referrer-policy", True, rp, "pass", "Referrer-Policy set")
        else:
            add("referrer-policy", True, rp, "warn", "Unrecognized Referrer-Policy value")
    else:
        add("referrer-policy", False, None, "warn", "Missing Referrer-Policy")

    # Permissions-Policy / Feature-Policy
    pp = headers.get("permissions-policy") or headers.get("feature-policy")
    if pp:
        add("permissions-policy", True, pp, "pass", "Permissions/Feature-Policy present")
    else:
        add("permissions-policy", False, None, "warn", "Missing Permissions-Policy / Feature-Policy")

    # Expect-CT (optional)
    expect_ct = headers.get("expect-ct")
    if expect_ct:
        add("expect-ct", True, expect_ct, "pass", "Expect-CT present")
    else:
        add("expect-ct", False, None, "warn", "Missing Expect-CT header")

    """ Server header disclosure (could be useful)
    server = headers.get("server")
    if server:
        add("server", True, server, "warn", "Server header discloses server software")
    else:
        add("server", False, None, "pass", "No Server header")
    """
    return results

def check_server_information_disclosure(
    headers: dict[str, str],
) -> Dict[str, Dict[str, Any]]:
    """
    Check for unnecessary server technology information disclosure.

    Args:
        headers: HTTP response headers with lowercase keys.

    Returns:
        A dictionary of security findings.
    """

    findings = {}

    # Server header
    server = headers.get("server")
    
    def add_finding(code: str, title: str, message: str, details: str):
        findings[code] = {
            "category": "headers",
            "title": title,
            "message": message,
            "details": details,
        }

    if server:
        add_finding(
            "SERVER_INFORMATION_DISCLOSURE",
            "Server Information Disclosure",
            "The Server header discloses information about the web server.",
            server
        )

    # X-Powered-By header
    powered_by = headers.get("x-powered-by")

    if powered_by:
        add_finding(
            "X_POWERED_BY_INFORMATION_DISCLOSURE",
            "X-Powered-By Information Disclosure",
            "The X-Powered-By header discloses information about the underlying technology.",
            powered_by
        )

    return findings

if __name__ == "__main__":
    # Test the security header checks with a sample headers dictionary
    test_headers = {
        "server": "nginx/1.18.0",
        "x-powered-by": "PHP/8.1",
        "x-content-type-options": "invalid-value", # This is an invalid value for testing
        "x-frame-options": "ALLOW", # This is an invalid value for testing
    }
    
    meta = {
        "is_https": True
    }

    print("--- Security Header Checks ---")
    findings = check_security_headers(test_headers, meta)
    for header, result in findings.items():
        print(f"{header}: {result}")
    print("\n--- Server Information Disclosure Checks ---")
    disclosure_findings = check_server_information_disclosure(test_headers)
    for finding, result in disclosure_findings.items():
        print(f"{finding}: {result}")
