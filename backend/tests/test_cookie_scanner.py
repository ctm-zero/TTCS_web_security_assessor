import sys
import os
import asyncio
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.scanners.cookie_scanner import (
    parse_cookie_header,
    parse_multiple_cookie_headers,
    fetch_and_scan_cookies,
)


def test_parse_cookie_header_valid():
    header_str = "sessionid=abc123; Path=/; HttpOnly; Secure; SameSite=Lax"
    result = parse_cookie_header(header_str)

    assert result["name"] == "sessionid"
    assert result["value"] == "abc123"
    assert result["httponly"] is True
    assert result["secure"] is True
    assert result["samesite"] == "Lax"


def test_parse_cookie_header_invalid():
    result = parse_cookie_header("")
    assert result == {}


def test_parse_multiple_cookie_headers():
    headers_list = [
        "sessionid=abc123; Path=/; HttpOnly; Secure",
        "userid=xyz789; Path=/",
    ]
    results = parse_multiple_cookie_headers(headers_list)

    assert len(results) == 2
    assert results[0]["name"] == "sessionid"
    assert results[1]["name"] == "userid"


@pytest.mark.asyncio
async def test_fetch_and_scan_cookies_real_url():
    test_url = "https://facebook.com"
    cookies, meta = await fetch_and_scan_cookies(test_url)

    assert "status_code" in meta
    assert "is_https" in meta
    assert meta["is_https"] is True
    assert isinstance(cookies, list)


if __name__ == "__main__":

    async def run_manual_test():
        test_url = "https://facebook.com"
        print(f"Testing live cookie scan for: {test_url}")

        cookies, meta = await fetch_and_scan_cookies(test_url)

        print("\nMeta:")
        for k, v in meta.items():
            print(f"  {k}: {v}")

        if cookies:
            print(f"\nCookies ({len(cookies)}):")
            for idx, cookie in enumerate(cookies, 1):
                print(f"  {idx}. {cookie['name']} = {cookie['value']}")
                print(
                    f"     httponly: {cookie['httponly']} | secure: {cookie['secure']} | samesite: {cookie['samesite']}"
                )
        else:
            print("\nNo cookies retrieved.")

    asyncio.run(run_manual_test())
