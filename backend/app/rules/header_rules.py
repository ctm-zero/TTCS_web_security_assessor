from typing import Any


def check_security_headers(
    headers: dict[str, str],
) -> list[dict[str, Any]]:
    """
    Evaluate HTTP security headers.

    Args:
        headers: HTTP response headers with lowercase keys.

    Returns:
        A list of security findings.
    """

    findings = []

    # ---------------------------------------------------------
    # Strict-Transport-Security (HSTS)
    # ---------------------------------------------------------
    hsts = headers.get("strict-transport-security")

    if not hsts:
        findings.append(
            {
                "code": "MISSING_HSTS",
                "category": "headers",
                "title": "Missing Strict-Transport-Security",
                "message": ("The Strict-Transport-Security header is missing."),
            }
        )

    # ---------------------------------------------------------
    # Content-Security-Policy (CSP)
    # ---------------------------------------------------------
    csp = headers.get("content-security-policy")

    if not csp:
        findings.append(
            {
                "code": "MISSING_CSP",
                "category": "headers",
                "title": "Missing Content-Security-Policy",
                "message": ("The Content-Security-Policy header is missing."),
            }
        )

    # ---------------------------------------------------------
    # X-Content-Type-Options
    # ---------------------------------------------------------
    x_content_type_options = headers.get("x-content-type-options")

    if not x_content_type_options:
        findings.append(
            {
                "code": "MISSING_X_CONTENT_TYPE_OPTIONS",
                "category": "headers",
                "title": "Missing X-Content-Type-Options",
                "message": ("The X-Content-Type-Options header is missing."),
            }
        )

    elif x_content_type_options.strip().lower() != "nosniff":
        findings.append(
            {
                "code": "INVALID_X_CONTENT_TYPE_OPTIONS",
                "category": "headers",
                "title": "Invalid X-Content-Type-Options",
                "message": (
                    "The X-Content-Type-Options header is not set " "to 'nosniff'."
                ),
            }
        )

    # ---------------------------------------------------------
    # X-Frame-Options
    # ---------------------------------------------------------
    x_frame_options = headers.get("x-frame-options")

    if not x_frame_options:
        findings.append(
            {
                "code": "MISSING_X_FRAME_OPTIONS",
                "category": "headers",
                "title": "Missing X-Frame-Options",
                "message": ("The X-Frame-Options header is missing."),
            }
        )

    elif x_frame_options.strip().upper() not in {
        "DENY",
        "SAMEORIGIN",
    }:
        findings.append(
            {
                "code": "INVALID_X_FRAME_OPTIONS",
                "category": "headers",
                "title": "Invalid X-Frame-Options",
                "message": ("The X-Frame-Options header has an invalid value."),
            }
        )

    # ---------------------------------------------------------
    # Referrer-Policy
    # ---------------------------------------------------------
    referrer_policy = headers.get("referrer-policy")

    if not referrer_policy:
        findings.append(
            {
                "code": "MISSING_REFERRER_POLICY",
                "category": "headers",
                "title": "Missing Referrer-Policy",
                "message": ("The Referrer-Policy header is missing."),
            }
        )

    # ---------------------------------------------------------
    # Cross-Origin-Resource-Policy (CORP)
    # ---------------------------------------------------------
    corp = headers.get("cross-origin-resource-policy")

    if not corp:
        findings.append(
            {
                "code": "MISSING_CORP",
                "category": "headers",
                "title": "Missing Cross-Origin-Resource-Policy",
                "message": ("The Cross-Origin-Resource-Policy header is missing."),
            }
        )

    # ---------------------------------------------------------
    # Cross-Origin-Opener-Policy (COOP)
    # ---------------------------------------------------------
    coop = headers.get("cross-origin-opener-policy")

    if not coop:
        findings.append(
            {
                "code": "MISSING_COOP",
                "category": "headers",
                "title": "Missing Cross-Origin-Opener-Policy",
                "message": ("The Cross-Origin-Opener-Policy header is missing."),
            }
        )

    # ---------------------------------------------------------
    # Cross-Origin-Embedder-Policy (COEP)
    # ---------------------------------------------------------
    coep = headers.get("cross-origin-embedder-policy")

    if not coep:
        findings.append(
            {
                "code": "MISSING_COEP",
                "category": "headers",
                "title": "Missing Cross-Origin-Embedder-Policy",
                "message": ("The Cross-Origin-Embedder-Policy header is missing."),
            }
        )

    # ---------------------------------------------------------
    # Cache-Control
    # ---------------------------------------------------------
    cache_control = headers.get("cache-control")

    if not cache_control:
        findings.append(
            {
                "code": "MISSING_CACHE_CONTROL",
                "category": "headers",
                "title": "Missing Cache-Control",
                "message": ("The Cache-Control header is missing."),
            }
        )

    return findings



# ---------------------------------------------------------
# Server Information Disclosure Checks
# If the server discloses its technology stack + specific version,
# it can be more valuable for fingerprinting.
# ---------------------------------------------------------
def check_server_information_disclosure(
    headers: dict[str, str],
) -> list[dict[str, Any]]:
    """
    Check for unnecessary server technology information disclosure.

    Args:
        headers: HTTP response headers with lowercase keys.

    Returns:
        A list of security findings.
    """

    findings = []

    # Server header
    server = headers.get("server")

    if server:
        findings.append(
            {
                "code": "SERVER_INFORMATION_DISCLOSURE",
                "category": "headers",
                "title": "Server Information Disclosure",
                "message": (
                    "The Server header discloses information about " "the web server."
                ),
                "details": server,
            }
        )

    # X-Powered-By header
    powered_by = headers.get("x-powered-by")

    if powered_by:
        findings.append(
            {
                "code": "X_POWERED_BY_INFORMATION_DISCLOSURE",
                "category": "headers",
                "title": "X-Powered-By Information Disclosure",
                "message": (
                    "The X-Powered-By header discloses information about "
                    "the underlying technology."
                ),
                "details": powered_by,
            }
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

    print("--- Security Header Checks ---")
    findings = check_security_headers(test_headers)
    for finding in findings:
        print(finding)

    print("\n--- Server Information Disclosure Checks ---")
    disclosure_findings = check_server_information_disclosure(test_headers)
    for finding in disclosure_findings:
        print(finding)

