from typing import Dict, Any
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import datetime


def check_tls_attributes(tls_data: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Evaluate important TLS attributes for security.

    Args:
        tls_data: dictionary representing TLS information with keys like `version`, `cipher`, etc.
    Returns:
        A dictionary containing the evaluation results for each TLS attribute.
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

    # TLS Version
    tls_version = tls_data.get("version")
    if tls_version:
        if tls_version in ("TLSv1.2", "TLSv1.3"):
            add(
                "tls_version",
                True,
                tls_version,
                "pass",
                f"TLS version {tls_version} is considered secure",
            )
        else:
            add(
                "tls_version",
                True,
                tls_version,
                "fail",
                f"TLS version {tls_version} is considered insecure",
            )
    else:
        add("tls_version", False, None, "fail", "TLS version information is missing")

    # Cipher Suite
    cipher_suite = tls_data.get("cipher")
    if cipher_suite:

        weak_ciphers = ["RC4", "DES", "3DES", "NULL", "MD5", "CBC"]
        if any(weak in cipher_suite for weak in weak_ciphers):
            add(
                "cipher_suite",
                True,
                cipher_suite,
                "fail",
                f"Cipher suite {cipher_suite} is considered weak",
            )
        else:
            add(
                "cipher_suite",
                True,
                cipher_suite,
                "pass",
                f"Cipher suite {cipher_suite} is considered secure",
            )
    else:
        add("cipher_suite", False, None, "fail", "Cipher suite information is missing")

    # Certificate Validity
    cert_pem = tls_data.get("certificate_pem")
    if cert_pem:
        try:
            cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            now = datetime.datetime.utcnow()
            expired_at = cert.not_valid_after
            days_left = (expired_at - now).days

            if days_left < 0:
                add(
                    "certificate_validity",
                    True,
                    f"Expired on {expired_at}",
                    "fail",
                    "Certificate has expired",
                )
            elif days_left < 30:
                add(
                    "certificate_validity",
                    True,
                    f"Expires on {expired_at}",
                    "warn",
                    f"Certificate will expire in {days_left} days",
                )
            else:
                add(
                    "certificate_validity",
                    True,
                    f"Valid from {cert.not_valid_before} to {cert.not_valid_after}",
                    "pass",
                    "Certificate is currently valid",
                )

            if cert.issuer == cert.subject:
                add(
                    "certificate_trust",
                    True,
                    "Self-Signed",
                    "fail",
                    "Certificate is self-signed and not trusted",
                )
            else:
                add(
                    "certificate_trust",
                    True,
                    "CA-Signed",
                    "pass",
                    "Certificate is signed by a trusted CA",
                )

        except Exception as e:
            add(
                "certificate_parsing",
                True,
                None,
                "fail",
                f"Failed to parse certificate: {str(e)}",
            )

    return results
