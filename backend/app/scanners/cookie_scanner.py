import httpx
from http.cookies import SimpleCookie
from typing import List, Dict, Any, Tuple
import asyncio


def parse_cookie_header(cookie_header: str) -> Dict[str, Any]:
    """Parse a Set-Cookie header string into a dictionary of cookie attributes."""
    cookie = SimpleCookie()

    try:
        cookie.load(cookie_header)
    except Exception:
        return {}

    for name, morsel in cookie.items():
        return {
            "name": name,
            "value": morsel.value,
            "path": morsel["path"] or None,
            "domain": morsel["domain"] or None,
            "httponly": bool(morsel["httponly"]),
            "secure": bool(morsel["secure"]),
            "samesite": morsel["samesite"] or None,
            "expires": morsel["expires"] or None,
            "max_age": morsel["max-age"] or None,
        }

    return {}


def parse_multiple_cookie_headers(
    cookie_headers: List[str],
) -> List[Dict[str, Any]]:
    """Parse multiple Set-Cookie header strings into a list of dictionaries."""
    cookies = []

    for header in cookie_headers:
        parsed_cookie = parse_cookie_header(header)

        if parsed_cookie:
            cookies.append(parsed_cookie)

    return cookies


async def fetch_and_scan_cookies(
    url: str,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Self-contained function to fetch URL and parse all returned cookies using SimpleCookie."""
    try:
        async with httpx.AsyncClient(follow_redirects=True) as client:
            response = await client.get(url)
            raw_cookies = response.headers.get_list("set-cookie")
            parsed_cookies = parse_multiple_cookie_headers(raw_cookies)

            meta = {
                "status_code": response.status_code,
                "final_url": str(response.url),
                "is_https": str(response.url.scheme).lower() == "https",
                "raw_count": len(raw_cookies),
            }
            return parsed_cookies, meta

    except httpx.RequestError as e:
        print(f"An error occurred while scanning cookies for {url}: {e}")
        return [], {
            "status_code": None,
            "final_url": url,
            "is_https": False,
            "raw_count": 0,
        }
