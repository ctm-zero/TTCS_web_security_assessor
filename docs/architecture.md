# Kiến trúc Hệ thống - Web Security Assessor

## 1. Tổng quan
Phần backend được xây dựng bằng **FastAPI** (Python), thiết kế theo mô hình phân tầng (layered architecture). Cách tổ chức này giúp tách biệt rõ ràng các chức năng, dễ bảo trì và dễ mở rộng khi cần bổ sung các tính năng kiểm tra bảo mật mới.

## 2. Sơ đồ kiến trúc

```text
      [ Client / Giao diện Frontend (React) ]
                       │
                       │ (Gửi yêu cầu HTTP POST /api/scan)
                       ▼ 
      [ Tầng điều hướng API (main.py) ]
                       │
                       ▼
      [ Tầng xử lý logic quét (scan_service.py) ]
         ├──> Trình quét & Quy tắc kiểm tra Header (header_rules.py)
         ├──> Trình quét & Quy tắc kiểm tra Cookie (cookie_rules.py)
         └──> Trình quét & Quy tắc kiểm tra TLS    (tls_rules.py)