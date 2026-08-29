import httpx
from typing import Tuple, Dict, Any, Optional
import asyncio


async def fetch_headers(
    url: str,
) -> Tuple[Optional[httpx.Response], Dict[str, str], Dict[str, Any]]:
    """Fetch a URL and return the raw response, a normalized headers dict, and metadata.

    Normalizes header keys by lowercasing them to avoid case-sensitivity bugs.

    Returns:
        tuple: (response or None, normalized_headers, meta)
            - normalized_headers: mapping of lowercased header name -> value
            - meta: dict with keys `status_code`, `final_url`, `is_https`
    """
    try:
        async with httpx.AsyncClient(follow_redirects=True) as client:
            response = await client.get(url)
            normalized = {k.lower(): v for k, v in response.headers.items()}
            meta = {
                "status_code": response.status_code,
                "final_url": str(response.url),
                "is_https": str(response.url.scheme).lower() == "https",
            }
            return response, normalized, meta
    except httpx.RequestError as e:
        print(f"An error occurred while requesting {url}: {e}")
        normalized: Dict[str, str] = {}
        meta = {
            "status_code": None,
            "final_url": url,
            "is_https": str(url).lower().startswith("https"),
        }
        return None, normalized, meta
