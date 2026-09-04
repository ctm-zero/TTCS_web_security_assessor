# Quy tắc & Tiêu chí Đánh giá Bảo mật

## 1. Kiểm tra HTTP Security Headers (Tiêu đề bảo mật)
Hệ thống tiến hành rà soát sự tồn tại và cấu hình của các HTTP header quan trọng:
- **Strict-Transport-Security (HSTS):** Kiểm tra xem website có bắt buộc người dùng truy cập qua HTTPS hay không và thời gian `max-age` có đủ lớn hay không.
- **Content-Security-Policy (CSP):** Phân tích các chính sách nội dung để phát hiện các cấu hình kém an toàn (như chứa các đoạn mã `unsafe-inline` hoặc `unsafe-eval`).
- **X-Frame-Options:** Đảm bảo trang web được bảo vệ chống lại tấn công dạng Clickjacking (giá trị chuẩn là `DENY` hoặc `SAMEORIGIN`).
- **X-Content-Type-Options:** Ngăn chặn trình duyệt tự ý đoán định kiểu dữ liệu (MIME-sniffing) với giá trị `nosniff`.
- **Referrer-Policy:** Đánh giá mức độ bảo vệ quyền riêng tư của người dùng và giới hạn các quyền truy cập tính năng trình duyệt.

## 2. Kiểm tra thuộc tính Cookie
Mỗi cookie trả về từ máy chủ sẽ được kiểm tra kỹ lưỡng các thuộc tính bảo mật sau:
- **HttpOnly:** Đảm bảo mã độc chạy ở phía client (JavaScript) không thể đánh cắp cookie (giúp giảm thiểu tấn công XSS).
- **Secure:** Đảm bảo cookie chỉ được truyền tải qua các kết nối mã hóa HTTPS.
- **SameSite:** Kiểm tra xem cookie có cấu hình `Lax` hoặc `Strict` để phòng chống tấn công giả mạo yêu cầu liên trang (CSRF) hay không.
- **Expires / Max-Age:** Đánh giá thời gian sống của cookie.

## 3. Kiểm tra chứng chỉ TLS / SSL
- **Phiên bản TLS:** Xác thực xem website có đang sử dụng các giao thức hiện đại và bảo mật như TLSv1.3 hay không.
- **Bộ mã hóa (Cipher Suite):** Đánh giá mức độ an toàn của các thuật toán mã hóa đang được sử dụng.
- **Tính hợp lệ của chứng chỉ:** Kiểm tra thời hạn hiệu lực của chứng chỉ số thông qua múi giờ chuẩn UTC để tránh tình trạng chứng chỉ bị hết hạn bất ngờ.