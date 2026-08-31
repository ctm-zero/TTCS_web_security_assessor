import ssl
import asyncio
from urllib.parse import urlparse

url = "https://www.facebook.com/"  # Replace with the URL you want to scan

parse_url = urlparse(url)
hostname = parse_url.hostname

print(f"Scanning TLS for {hostname}...")

port = parse_url.port or (443 if parse_url.scheme == "https" else 80)
print(f"Port: {port}")

context = ssl.create_default_context()

context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

print("SSL context created. Attempting to connect...")

async def fetch_tls_test():
    try:
        print(f"Connecting to {hostname}:{port}...")
        reader, writer = await asyncio.open_connection(hostname, port, ssl=context)

        ssl_object = writer.get_extra_info("ssl_object")

        if ssl_object:
            # Get the raw certificate in binary form (CERT_NONE mode)
            raw_cert = ssl_object.getpeercert(binary_form=True)
            print(f"Retrieved raw certificate: {len(raw_cert)} bytes")

            print(f"TLS version: {ssl_object.version()}")
            print(f"Cipher Suite : {ssl_object.cipher()}")

        writer.close()
        await writer.wait_closed()
        print("Connection closed.")
    except Exception as e:
        print(f"Connection failed : {e}")

asyncio.run(fetch_tls_test())