from fastapi import APIRouter, HTTPException

from backend.app.models.scan_request import ScanRequest
from backend.app.services.scan_service import scan_url


router = APIRouter()


@router.post("/api/scan")
async def run_scan(request: ScanRequest):
    try:
        return await scan_url(str(request.url))

    except Exception as e:
        print(f"Error during scan: {e}")
        raise HTTPException(
            status_code=500,
            detail="An error occurred while scanning the target.",
        )