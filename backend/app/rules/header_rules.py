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
    headers: Dict[str, str], meta: Dict[str, Any]
) -> Dict[str, Dict[str, Any]]:
    """Evaluate important security headers per OWASP Security Response Header Cheat Sheet.

    Args:
        headers: normalized headers (lowercased keys)
        meta: response metadata containing `is_https` (bool)

    Returns:
        mapping header -> result dict {present, value, status, reason}
    """
    results: Dict[str, Dict[str, Any]] = {}

    def add(
        name: str,
        present: bool,
        value: str = None,
        status: str = "warn",
        reason: str = "",
    ):
        results[name] = {
            "present": present,
            "value": value,
            "status": status,
            "reason": reason,
        }

    is_https = bool(meta.get("is_https"))
    """
    The following headers are core:
    - Strict-Transport-Security (HSTS)
    - Content-Security-Policy (CSP)
    - X-Frame-Options
    - X-Content-Type-Options
    - Referrer-Policy
    """

    # Strict-Transport-Security (HSTS)
    hsts = headers.get("strict-transport-security")
    if is_https:
        if hsts:
            max_age = _parse_max_age(hsts)
            if max_age >= 15768000: # 6 months in seconds
                add(
                    "strict-transport-security",
                    True,
                    hsts,
                    "pass",
                    "HSTS set with adequate max-age",
                )
                if "preload" in hsts.lower():
                    results["strict-transport-security"]["reason"] += " and preloaded"
            else:
                add(
                    "strict-transport-security",
                    True,
                    hsts,
                    "warn",
                    "HSTS max-age is low",
                )
        else:
            add(
                "strict-transport-security",
                False,
                None,
                "fail",
                "Missing HSTS on HTTPS response",
            )
    else:
        add(
            "strict-transport-security",
            bool(hsts),
            hsts,
            "warn",
            "HSTS only applies to HTTPS responses",
        )

    # Content-Security-Policy
    csp = headers.get("content-security-policy")
    if csp:
        if "unsafe-inline" in csp or "unsafe-eval" in csp:
            add(
                "content-security-policy",
                True,
                csp,
                "warn",
                "CSP contains unsafe directives",
            )
        else:
            add("content-security-policy", True, csp, "pass", "CSP present")
            if "default-src 'none'" in csp:
                results["content-security-policy"]["reason"] += " and default-src 'none'"
            if "form-action 'none'" in csp or "form-action 'self'" in csp:
                results["content-security-policy"]["reason"] += " and form-action restricted"
    else:
        add("content-security-policy", False, None, "fail", "Missing CSP")

    # X-Frame-Options
    xfo = headers.get("x-frame-options")
    if xfo:
        if xfo.lower() in ("deny", "sameorigin"):
            add("x-frame-options", True, xfo, "pass", "X-Frame-Options set")
        else:
            add(
                "x-frame-options",
                True,
                xfo,
                "warn",
                "X-Frame-Options value is uncommon",
            )
    else:
        add(
            "x-frame-options",
            False,
            None,
            "fail",
            "Missing X-Frame-Options (clickjacking protection)",
        )

    # X-Content-Type-Options
    xcto = headers.get("x-content-type-options")
    if xcto and xcto.lower() == "nosniff":
        add("x-content-type-options", True, xcto, "pass", "nosniff set")
    else:
        add(
            "x-content-type-options",
            bool(xcto),
            xcto,
            "warn",
            "Missing or incorrect X-Content-Type-Options",
        )

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
            add(
                "referrer-policy",
                True,
                rp,
                "warn",
                "Unrecognized Referrer-Policy value",
            )
    else:
        add("referrer-policy", False, None, "warn", "Missing Referrer-Policy")
        
    """
    The following headers are optional but recommended:
    -X-Permitted-Cross-Domain-Policies
    -Clear-Site-Data
    -Cross-Origin-Resource-Policy (CORP)
    -Cross-Origin-Embedder-Policy (COEP)
    -Cross-Origin-Opener-Policy (COOP)
    -Cache-Control
    -Integrity-Policy
    """
    
    # X-Permitted-Cross-Domain-Policies
    xpcdp = headers.get("x-permitted-cross-domain-policies")
    if xpcdp:
        if xpcdp.lower() in ("none", "master-only"):
            add(
                "x-permitted-cross-domain-policies",
                True,
                xpcdp,
                "pass",
                "X-Permitted-Cross-Domain-Policies set to a secure value",
            )
        else:
            add(
                "x-permitted-cross-domain-policies",
                True,
                xpcdp,
                "warn",
                "X-Permitted-Cross-Domain-Policies set to an insecure value",
            )
    
    # Clear-Site-Data
    csd =headers.get("clear-site-data")
    if csd :
        add(
            "clear-site-data",
            True,
            csd,
            "pass",
            "Clear-Site-Data header is present",
        )
    
    # Cross-Origin-Resource-Policy (CORP)
    corp = headers.get("cross-origin-resource-policy")
    if corp:
        if corp.lower() in ("same-origin", "same-site"):
            add(
                "cross-origin-resource-policy",
                True,
                corp,
                "pass",
                "Cross-Origin-Resource-Policy set to a secure value",
            )
        else:
            add(
                "cross-origin-resource-policy",
                True,
                corp,
                "warn",
                "Cross-Origin-Resource-Policy set to an insecure value",
            )
            
    # Cross-Origin-Embedder-Policy (COEP)
    coep = headers.get("cross-origin-embedder-policy")
    if coep:
        if coep.lower() == "require-corp":
            add(
                "cross-origin-embedder-policy",
                True,
                coep,
                "pass",
                "Cross-Origin-Embedder-Policy set to a secure value",
            )
        else:
            add(
                "cross-origin-embedder-policy",
                True,
                coep,
                "warn",
                "Cross-Origin-Embedder-Policy set to an insecure value",
            )
            
    # Cross-Origin-Opener-Policy (COOP)
    coop = headers.get("cross-origin-opener-policy")
    if coop:
        if coop.lower() in ("same-origin", "same-origin-allow-popups"):
            add(
                "cross-origin-opener-policy",
                True,
                coop,
                "pass",
                "Cross-Origin-Opener-Policy set to a secure value",
            )
        else:
            add(
                "cross-origin-opener-policy",
                True,
                coop,
                "warn",
                "Cross-Origin-Opener-Policy set to an insecure value",
            )
    
    #Cache-Control
    cache_control = headers.get("cache-control")
    if cache_control:
        add(
            "cache-control",
            True,
            cache_control,
            "pass",
            "Cache-Control header is present",
        )
        
    # Integrity-Policy
    integrity_policy = headers.get("integrity-policy")
    if integrity_policy:
        add(
            "integrity-policy",
            True,
            integrity_policy,
            "pass",
            "Integrity-Policy header is present",
        )
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

    def add_finding(
        name: str,
        present: bool,
        value: str = None,
        status: str = "warn",
        reason: str = "",
    ):
        findings[name] = {
            "present": present,
            "value": value,
            "status": status,
            "reason": reason,
        }

    if server:
        add_finding(
            "server", True, server, "warn", "Server header discloses server software"
        )
    else:
        add_finding("server", False, None, "pass", "No Server header")

    # X-Powered-By header
    x_powered_by = headers.get("x-powered-by")
    if x_powered_by:
        add_finding(
            "x-powered-by",
            True,
            x_powered_by,
            "warn",
            "X-Powered-By header discloses technology stack",
        )
    else:
        add_finding("x-powered-by", False, None, "pass", "No X-Powered-By header")

    return findings


if __name__ == "__main__":
    # Test the security header checks with a sample headers dictionary
    test_headers = {
        "server": "nginx/1.18.0",
        "x-powered-by": "PHP/8.1",
        "x-content-type-options": "invalid-value",  # This is an invalid value for testing
        "x-frame-options": "ALLOW",  # This is an invalid value for testing
    }

    meta = {"is_https": True}

    print("--- Security Header Checks ---")
    findings = check_security_headers(test_headers, meta)
    for header, result in findings.items():
        print(f"{header}: {result}")
    print("\n--- Server Information Disclosure Checks ---")
    disclosure_findings = check_server_information_disclosure(test_headers)
    for finding, result in disclosure_findings.items():
        print(f"{finding}: {result}")
