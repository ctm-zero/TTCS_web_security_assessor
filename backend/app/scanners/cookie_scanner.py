from http.cookies import SimpleCookie
from typing import Any


def parse_cookie_header(cookie_header: str) -> dict[str, Any]:
    """
    Parse a Set-Cookie header string into a dictionary of cookie attributes.
    """
    cookie = SimpleCookie()

    try:
        cookie.load(cookie_header)
    except Exception:
        return {}

    for name, morsel in cookie.items():
        return {
            "name": name,
            "path": morsel["path"] or None,
            "domain": morsel["domain"] or None,
            "httponly": bool(morsel["httponly"]),
            "secure": bool(morsel["secure"]),
            "samesite": morsel["samesite"] or None,
            "expires": morsel["expires"] or None,
            "max_age": morsel["max-age"] or None,
        }

    return {}


def parse_cookie_headers(
    cookie_headers: list[str],
) -> list[dict[str, Any]]:
    """
    Parse multiple Set-Cookie header strings into a list of dictionaries.
    """
    cookies = []

    for header in cookie_headers:
        parsed_cookie = parse_cookie_header(header)

        if parsed_cookie:
            cookies.append(parsed_cookie)

    return cookies

# Example usage
if __name__ == "__main__":
    cookie_headers = [
        "sessionid=abc123; Path=/; HttpOnly; Secure; SameSite=Lax",
        "userid=xyz789; Path=/; Domain=example.com; Expires=Wed, 09 Jun 2021 10:18:14 GMT",
    ]

    parsed_cookies = parse_cookie_headers(cookie_headers)
    for cookie in parsed_cookies:
        print(cookie)