from typing import Dict, Any
import re


def check_cookie_attributes(cookie: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Evaluate important cookie attributes for security.

    Args:
        cookie: dictionary representing a parsed cookie with keys like `secure`, `httponly`, etc.

    Returns:
        A dictionary containing the evaluation results for each cookie attribute.
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

    # HttpOnly
    http_only = cookie.get("httponly")
    if http_only:
        add("httponly", True, http_only, "pass", "Cookie has HttpOnly attribute set")
    else:
        add("httponly", False, None, "fail", "Cookie is missing HttpOnly attribute")

    # Secure
    secure = cookie.get("secure")
    if secure:
        add("secure", True, secure, "pass", "Cookie has Secure attribute set")
    else:
        add("secure", False, None, "fail", "Cookie is missing Secure attribute")

    # SameSite
    same_site = cookie.get("samesite")
    if same_site:
        if same_site.lower() in ("lax", "strict"):
            add(
                "samesite",
                True,
                same_site,
                "pass",
                "Cookie has SameSite attribute set to a secure value",
            )
        else:
            add(
                "samesite",
                True,
                same_site,
                "warn",
                "Cookie has SameSite attribute set to an insecure value",
            )
    else:
        add("samesite", False, None, "fail", "Cookie is missing SameSite attribute")

    # Expires
    expires = cookie.get("expires")
    if expires:
        add("expires", True, expires, "pass", "Cookie has Expires attribute set")
    else:
        add("expires", False, None, "warn", "Cookie is missing Expires attribute")

    # Max-Age
    max_age = cookie.get("max_age")
    if max_age is not None:
        add("max_age", True, str(max_age), "pass", "Cookie has Max-Age attribute set")
    else:
        add("max_age", False, None, "warn", "Cookie is missing Max-Age attribute")

    return results
