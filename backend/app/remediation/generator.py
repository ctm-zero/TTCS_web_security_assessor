from typing import Any


REMEDIATION_RULES = {
    "header:strict-transport-security": {
        "title": "HTTP Strict Transport Security (HSTS)",
        "recommendation": {
            "nginx": (
                'add_header Strict-Transport-Security '
                '"max-age=31536000; includeSubDomains" always;'
            ),
            "apache": (
                'Header always set Strict-Transport-Security '
                '"max-age=31536000; includeSubDomains"'
            ),
        },
        "warnings": [
            "Chỉ áp dụng khi website đã hoạt động ổn định trên HTTPS.",
            "includeSubDomains có thể ảnh hưởng tới các subdomain chưa hỗ trợ HTTPS.",
        ],
    },

    "header:content-security-policy": {
        "title": "Content-Security-Policy (CSP)",
        "recommendation": {
            "nginx": (
                'add_header Content-Security-Policy '
                '"default-src \'self\'; object-src \'none\'; '
                'base-uri \'self\'; frame-ancestors \'self\'" always;'
            ),
            "apache": (
                'Header always set Content-Security-Policy '
                '"default-src \'self\'; object-src \'none\'; '
                'base-uri \'self\'; frame-ancestors \'self\'"'
            ),
        },
        "warnings": [
            "CSP có thể ảnh hưởng tới JavaScript, CSS, CDN, font, image hoặc iframe.",
            "Cần điều chỉnh policy theo tài nguyên thực tế của ứng dụng.",
        ],
    },

    "header:x-frame-options": {
        "title": "X-Frame-Options",
        "recommendation": {
            "nginx": (
                'add_header X-Frame-Options "DENY" always;'
            ),
            "apache": (
                'Header always set X-Frame-Options "DENY"'
            ),
        },
        "warnings": [
            "DENY sẽ ngăn website được nhúng trong frame hoặc iframe.",
            "Nếu CSP đã sử dụng frame-ancestors, cần kiểm tra để tránh cấu hình không phù hợp.",
        ],
    },

    "header:x-content-type-options": {
        "title": "X-Content-Type-Options",
        "recommendation": {
            "nginx": (
                'add_header X-Content-Type-Options "nosniff" always;'
            ),
            "apache": (
                'Header always set X-Content-Type-Options "nosniff"'
            ),
        },
        "warnings": [
            "Website cần khai báo Content-Type chính xác cho tài nguyên được phục vụ.",
        ],
    },

    "header:referrer-policy": {
        "title": "Referrer-Policy",
        "recommendation": {
            "nginx": (
                'add_header Referrer-Policy '
                '"strict-origin-when-cross-origin" always;'
            ),
            "apache": (
                'Header always set Referrer-Policy '
                '"strict-origin-when-cross-origin"'
            ),
        },
        "warnings": [
            "Thay đổi chính sách có thể làm giảm lượng thông tin Referrer được gửi tới website khác.",
        ],
    },

    "header:server": {
        "title": "Server Header",
        "recommendation": {
            "nginx": (
                "# Giảm thiểu thông tin phiên bản Server được công khai."
            ),
            "apache": (
                "ServerTokens Prod\n"
                "ServerSignature Off"
            ),
        },
        "warnings": [
            "Không nên xóa header bằng cách làm ảnh hưởng tới các header cần thiết khác.",
        ],
    },

    "header:x-powered-by": {
        "title": "X-Powered-By",
        "recommendation": {
            "nginx": (
                "# Loại bỏ hoặc ẩn X-Powered-By tại tầng ứng dụng/reverse proxy."
            ),
            "apache": (
                "# Loại bỏ hoặc ẩn X-Powered-By tại tầng ứng dụng/reverse proxy."
            ),
        },
        "warnings": [
            "Cách loại bỏ header phụ thuộc vào framework hoặc ứng dụng đang sử dụng.",
        ],
    },

    "tls:tls_version": {
        "title": "TLS Version",
        "recommendation": {
            "nginx": (
                "ssl_protocols TLSv1.2 TLSv1.3;"
            ),
            "apache": (
                "SSLProtocol -all +TLSv1.2 +TLSv1.3"
            ),
        },
        "warnings": [
            "Có thể ảnh hưởng tới các client cũ chỉ hỗ trợ TLS phiên bản thấp hơn.",
        ],
    },

    "tls:cipher_suite": {
        "title": "TLS Cipher Suite",
        "recommendation": {
            "nginx": (
                "# Cấu hình cipher suite phù hợp với phiên bản TLS "
                "và chính sách bảo mật của hệ thống."
            ),
            "apache": (
                "# Cấu hình SSLCipherSuite phù hợp với phiên bản TLS "
                "và chính sách bảo mật của hệ thống."
            ),
        },
        "warnings": [
            "Không nên áp dụng một danh sách cipher cố định mà không kiểm tra "
            "khả năng tương thích với TLS version và client."
        ],
    },

    "tls:certificate_parsing": {
        "title": "TLS Certificate",
        "recommendation": {
            "nginx": (
                "# Kiểm tra và thay thế certificate bằng certificate hợp lệ."
            ),
            "apache": (
                "# Kiểm tra và thay thế certificate bằng certificate hợp lệ."
            ),
        },
        "warnings": [
            "Cần xác định đúng certificate đang được sử dụng bởi TLS endpoint.",
        ],
    },

    "tls:certificate_validity": {
        "title": "TLS Certificate Validity",
        "recommendation": {
            "nginx": (
                "# Cập nhật certificate mới tại cấu hình TLS của Nginx."
            ),
            "apache": (
                "SSLCertificateFile /path/to/new/certificate.crt\n"
                "SSLCertificateKeyFile /path/to/private.key"
            ),
        },
        "warnings": [
            "Cần thay certificate trước khi certificate hiện tại hết hạn.",
            "Sau khi thay đổi cần kiểm tra lại certificate chain và cấu hình HTTPS.",
        ],
    },

    "tls:certificate_trust": {
        "title": "TLS Certificate Trust",
        "recommendation": {
            "nginx": (
                "# Thay certificate bằng certificate được CA tin cậy ký."
            ),
            "apache": (
                "# Thay certificate bằng certificate được CA tin cậy ký."
            ),
        },
        "warnings": [
            "Certificate cần có chain tin cậy đối với client sử dụng website.",
        ],
    },
}


COOKIE_REMEDIATION = {
    "samesite": {
        "title": "Cookie SameSite",
        "recommendation": (
            "Thiết lập SameSite=Lax hoặc Strict tùy yêu cầu của ứng dụng."
        ),
        "warnings": [
            "Có thể ảnh hưởng tới các chức năng yêu cầu cookie trong ngữ cảnh cross-site.",
        ],
    },
    "httponly": {
        "title": "Cookie HttpOnly",
        "recommendation": (
            "Thiết lập thuộc tính HttpOnly cho cookie phiên."
        ),
        "warnings": [
            "Cookie sẽ không thể được truy cập trực tiếp bằng JavaScript phía client.",
        ],
    },
    "secure": {
        "title": "Cookie Secure",
        "recommendation": (
            "Thiết lập thuộc tính Secure cho cookie khi website sử dụng HTTPS."
        ),
        "warnings": [
            "Cookie chỉ được gửi qua kết nối HTTPS.",
        ],
    },
}


def _get_cookie_remediation(reason: str) -> dict[str, Any] | None:
    """Xác định remediation cho cookie dựa trên lý do finding."""

    reason_lower = reason.lower()

    if "samesite" in reason_lower:
        rule = COOKIE_REMEDIATION["samesite"]
    elif "httponly" in reason_lower:
        rule = COOKIE_REMEDIATION["httponly"]
    elif "secure" in reason_lower:
        rule = COOKIE_REMEDIATION["secure"]
    else:
        return None

    return {
        "title": rule["title"],
        "recommendation": {
            "application": rule["recommendation"],
        },
        "warnings": rule["warnings"],
    }


def generate_remediation(scoring_report: dict[str, Any]) -> dict[str, Any]:
    """
    Sinh cấu hình khuyến nghị từ scoring report.

    Generator chỉ xử lý những finding đã được score_engine đưa vào
    scoring_report["issues"]. Nó không tự tính risk level hoặc score.
    """

    remediation = []

    issues = scoring_report.get("issues", {})

    for severity, severity_issues in issues.items():

        if not severity_issues:
            continue

        for issue_id, issue in severity_issues.items():

            category = issue.get("category", "")
            item = issue.get("item", "")
            reason = issue.get("reason", "")

            # Không sinh remediation cho finding không hợp lệ.
            if not category or not item:
                continue

            # Cookie được xử lý riêng vì issue item là tên cookie,
            # không phải tên thuộc tính bị lỗi.
            if category == "cookie":
                cookie_rule = _get_cookie_remediation(reason)

                if cookie_rule is None:
                    remediation.append({
                        "id": issue_id,
                        "title": item,
                        "severity": severity,
                        "reason": reason,
                        "recommendation": {},
                        "warnings": [
                            "Chưa có cấu hình remediation chi tiết cho finding này."
                        ],
                    })
                    continue

                remediation.append({
                    "id": issue_id,
                    "title": cookie_rule["title"],
                    "severity": severity,
                    "reason": reason,
                    "recommendation": cookie_rule["recommendation"],
                    "warnings": cookie_rule["warnings"],
                })

                continue

            # Các finding header / TLS dùng knowledge base.
            rule = REMEDIATION_RULES.get(issue_id)

            if rule is None:
                remediation.append({
                    "id": issue_id,
                    "title": item,
                    "severity": severity,
                    "reason": reason,
                    "recommendation": {},
                    "warnings": [
                        "Chưa có cấu hình remediation chi tiết cho finding này."
                    ],
                })
                continue

            remediation.append({
                "id": issue_id,
                "title": rule["title"],
                "severity": severity,
                "reason": reason,
                "recommendation": rule["recommendation"],
                "warnings": rule["warnings"],
            })

    return {
        "remediation": remediation
    }