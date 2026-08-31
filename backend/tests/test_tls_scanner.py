import sys
import os
import asyncio
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.scanners.tls_scanner import fetch_tls

import pytest
from app.scanners.tls_scanner import fetch_tls


@pytest.mark.asyncio
async def test_fetch_tls_success():
    test_url = "https://facebook.com"
    tls_data, meta = await fetch_tls(test_url)

    assert meta["error"] is None
    assert meta["hostname"] == "facebook.com"
    assert meta["port"] == 443

    assert tls_data["version"] is not None
    assert tls_data["certificate_pem"] is not None


if __name__ == "__main__":

    async def run_manual_test():
        test_url = "https://facebook.com"
        print(f"Testing live connection to: {test_url}")

        tls_data, meta = await fetch_tls(test_url)

        print("\nMeta:")
        for k, v in meta.items():
            print(f"  {k}: {v}")

        if tls_data:
            print(f"\nTLS Data ({len(tls_data)})")
            for idx, (k, v) in enumerate(list(tls_data.items())[:5], 1):
                # Kiểm tra nếu là chứng chỉ thì format hiển thị riêng
                if k == "certificate_pem" and isinstance(v, str):
                    print(f"  {idx}. {k} (len: {len(v)} bytes):\n{v}")
                else:
                    print(f"  {idx}. {k} = {v}")
        else:
            print("\nNo TLS data retrieved.")

    asyncio.run(run_manual_test())
