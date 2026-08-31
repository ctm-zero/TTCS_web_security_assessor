import ssl
import asyncio
from urllib.parse import urlparse
from typing import Tuple, Dict, Any, Optional


async def fetch_tls(url: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:

    tls_data: Dict[str, Any] = {
        "version": None,
        "cipher": None,
        "certificate_pem": None,
    }
    meta: Dict[str, Any] = {"hostname": None, "port": 443, "error": None}

    parse_url = urlparse(url)
    hostname = parse_url.hostname

    if not hostname:
        meta["error"] = "Invalid URL"
        return tls_data, meta

    meta["hostname"] = hostname
    port = parse_url.port or 443
    meta["port"] = port

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(hostname, port, ssl=context), timeout=10.0
        )
        ssl_obj = writer.get_extra_info("ssl_object")

        if ssl_obj:
            tls_data["version"] = ssl_obj.version()

            cipher_info = ssl_obj.cipher()
            if cipher_info:
                tls_data["cipher"] = cipher_info[0]

            raw_cert = ssl_obj.getpeercert(binary_form=True)
            if raw_cert:
                tls_data["certificate_pem"] = ssl.DER_cert_to_PEM_cert(raw_cert)

        writer.close()
        await writer.wait_closed()

    except asyncio.TimeoutError:
        meta["error"] = "Connection timed out"

    except Exception as e:
        meta["error"] = f"Connection failed: {str(e)}"

    return tls_data, meta
