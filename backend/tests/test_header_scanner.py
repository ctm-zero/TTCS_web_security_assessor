import sys
import os
import asyncio
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.scanners.header_scanner import fetch_headers


@pytest.mark.asyncio
async def test_fetch_headers_real_url():
    test_url = "https://lapazyenthuy.com/"
    response, normalized_headers, meta = await fetch_headers(test_url)

    assert "status_code" in meta
    assert "is_https" in meta
    assert meta["is_https"] is True

    for k in normalized_headers.keys():
        assert k == k.lower()


if __name__ == "__main__":

    async def run_manual_test():
        test_url = "https://facebook.com"
        print(f"Testing live connection to: {test_url}")

        response, headers, meta = await fetch_headers(test_url)

        print("\nMeta:")
        for k, v in meta.items():
            print(f"  {k}: {v}")

        if headers:
            print(f"\nHeaders ({len(headers)}):")
            for idx, (k, v) in enumerate(list(headers.items())[:5], 1):
                print(f"  {idx}. {k} = {v}")
        else:
            print("\nNo headers retrieved.")

    asyncio.run(run_manual_test())
