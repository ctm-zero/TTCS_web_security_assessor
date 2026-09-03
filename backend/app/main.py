from fastapi import FastAPI, HTTPException, Request  # type: ignore[reportMissingImports]
from fastapi.middleware.cors import CORSMiddleware  # type: ignore[reportMissingImports]
from pydantic import BaseModel, HttpUrl
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from services import scan_service

app = FastAPI(title="Web Security Assessor API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_header(request: Request, call_next):
    response = await call_next(request)
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["server"] = "SecureServer"
    return response


@app.get("/")
def root():
    return {"message": "Web Security Assessor API"}


@app.get("/health")
def health():
    return {"status": "ok"}


class ScanRequest(BaseModel):
    url: HttpUrl


@app.post("/api/scan")
async def run_scan(request: ScanRequest):
    target_url = str(request.url)
    try:
        scan_results = await scan_service.scan_url(target_url)
        return scan_results
    except Exception as e:
        print(f"Error during scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))
