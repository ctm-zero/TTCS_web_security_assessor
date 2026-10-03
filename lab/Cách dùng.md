```bash
cd lab

docker compose up -d 
docker compose ps # all 4 should be "running" 
docker compose logs apache-secure # no errors 
docker compose logs nginx-secure

# Kiểm tra các target bằng curl
curl -sI http://localhost:8080
curl -sI --cacert certs/ca.crt https://localhost:9443
curl -sI http://localhost:9080
curl -sI --cacert certs/ca.crt https://localhost:9543

# Bật venv, tin cái cert local tạo trong ./certs
cd ..    # back to the project root
source venv/bin/activate
export SSL_CERT_FILE=$(pwd)/lab/certs/ca.crt
```

## Bảng các target
Đuôi  port:
- 80: Không có HTTPS
- 43: Có HTTPS
Bắt đầu port:
- 8xxx: Không an toàn
- 9xxx: An toàn

| Name                | URLs                                              | Software   | Config                                                                                                                            | Expected result |
| ------------------- | ------------------------------------------------- | ---------- | --------------------------------------------------------------------------------------------------------------------------------- | --------------- |
| **nginx-insecure**  | `http://localhost:8080`, `https://localhost:8443` | Nginx 1.27 | No security headers, `Server: nginx/1.27.5` leaked, `X-Powered-By: PHP/7.4.3`, cookie `sid=abc123` with no flags                  | Grade F         |
| **nginx-secure**    | `http://localhost:9080`, `https://localhost:9443` | Nginx 1.27 | All security headers, version hidden, cookie `__Host-sid` with Secure, HttpOnly and SameSite=Strict, port 9080 redirects to HTTPS | Grade A+        |
| **apache-insecure** | `http://localhost:8180`, `https://localhost:8543` | Apache 2.4 | Same weaknesses as nginx-insecure, with `ServerTokens Full`                                                                       | Grade F         |
| **apache-secure**   | `http://localhost:9180`, `https://localhost:9543` | Apache 2.4 | Same hardening as nginx-secure, with `ServerTokens Prod`                                                                          | Grade A+        |
