from typing import Dict, Any


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

        weak_ciphers = ["RC4", "DES", "3DES", "NULL"]
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

    return results
