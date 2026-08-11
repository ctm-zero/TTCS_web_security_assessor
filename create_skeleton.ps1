Write-Host "[+] Creating project skeleton in current directory..."
Write-Host "[+] Location: $(Get-Location)"

# =========================
# Helper
# =========================

function New-EmptyFile {
    param (
        [string]$Path
    )

    if (-not (Test-Path $Path)) {
        New-Item -ItemType File -Path $Path | Out-Null
    }
}

# =========================
# Backend
# =========================

$directories = @(
    "backend/app/api",
    "backend/app/scanners",
    "backend/app/rules",
    "backend/app/scoring",
    "backend/app/remediation/templates/nginx",
    "backend/app/remediation/templates/apache",
    "backend/app/models",
    "backend/app/services",
    "backend/tests",

    "frontend",

    "lab/vulnerable/nginx",
    "lab/vulnerable/apache",
    "lab/vulnerable/web",

    "lab/hardened/nginx",
    "lab/hardened/apache",

    "lab/poc/clickjacking",
    "lab/poc/cookie-demo",
    "lab/poc/hsts-demo",

    "docs"
)

foreach ($dir in $directories) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
}

# =========================
# Python package files
# =========================

$files = @(
    "backend/app/__init__.py",

    "backend/app/api/__init__.py",
    "backend/app/api/scan.py",

    "backend/app/scanners/__init__.py",
    "backend/app/scanners/header_scanner.py",
    "backend/app/scanners/cookie_scanner.py",
    "backend/app/scanners/tls_scanner.py",

    "backend/app/rules/__init__.py",
    "backend/app/rules/header_rules.py",
    "backend/app/rules/cookie_rules.py",
    "backend/app/rules/tls_rules.py",

    "backend/app/scoring/__init__.py",
    "backend/app/scoring/score_engine.py",

    "backend/app/remediation/__init__.py",
    "backend/app/remediation/generator.py",

    "backend/app/models/__init__.py",
    "backend/app/models/finding.py",
    "backend/app/models/scan_request.py",
    "backend/app/models/scan_result.py",

    "backend/app/services/__init__.py",
    "backend/app/services/scan_service.py",

    "backend/requirements.txt",
    "backend/Dockerfile",

    "frontend/.gitkeep",

    "lab/docker-compose.yml",

    "docs/architecture.md",
    "docs/rules.md",
    "docs/scoring.md",
    "docs/test-cases.md",

    "docker-compose.yml"
)

foreach ($file in $files) {
    New-EmptyFile $file
}

# =========================
# FastAPI main.py
# =========================

if (-not (Test-Path "backend/app/main.py")) {

@'
from fastapi import FastAPI

app = FastAPI(
    title="Web Security Assessor API",
    version="0.1.0"
)


@app.get("/")
def root():
    return {
        "message": "Web Security Assessor API"
    }


@app.get("/health")
def health():
    return {
        "status": "ok"
    }
'@ | Set-Content "backend/app/main.py" -Encoding UTF8

}

# =========================
# .gitignore
# =========================

if (-not (Test-Path ".gitignore")) {

@'
# Python
__pycache__/
*.py[cod]
.venv/
venv/
.pytest_cache/

# Node
node_modules/
dist/
build/

# Environment
.env
.env.*
!.env.example

# Certificates / Secrets
*.key
*.pem

# IDE
.vscode/
.idea/

# OS
.DS_Store
Thumbs.db

# Logs
*.log
logs/
'@ | Set-Content ".gitignore" -Encoding UTF8

}

# =========================
# README
# =========================

if (-not (Test-Path "README.md")) {

@'
# Web Security Assessor

Ứng dụng Web hỗ trợ rà soát, đánh giá và gia cố
các cấu hình an toàn có thể quan sát từ bên ngoài Website.

## Tech Stack

### Backend
- Python
- FastAPI

### Frontend
- React
- TypeScript
- Vite

### Test Lab
- Docker
- Docker Compose
- Nginx
- Apache

## Project Structure

- backend/  Backend API và scanner
- frontend/ React Dashboard
- lab/      Môi trường thử nghiệm và PoC
- docs/     Tài liệu dự án
'@ | Set-Content "README.md" -Encoding UTF8

}

Write-Host ""
Write-Host "[+] Skeleton created successfully!"
Write-Host ""

Get-ChildItem -Recurse |
    Where-Object { $_.FullName -notmatch "\\.git\\" } |
    Select-Object FullName