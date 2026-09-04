import sys
import os
import asyncio
import json
from typing import Dict, Any

from backend.app.services.scan_service import scan_url

def score_results(scan_results: Dict[str, Any]) -> Dict[str, Any]:
    """Score the scan results based on predefined rules and return a structured scoring report."""
    
    # Initialize scoring report
    scoring_report: Dict[str, Any] = {
        "meta": scan_results.get("meta", {}),
        "scores": {
            "headers": 0,
            "cookies": 0,
            "tls": 0,
        },
        "details": {
            "headers": {},
            "cookies": [],
            "tls": {},
        },
    }

    # Score Headers
    # Main headers
    header_findings = scan_results.get("headers", {})
    scoring_report["details"]["headers"] = header_findings
    header_score = 0
    for header, value in header_findings.items():
        status = value.get("status")
        reason = value.get("reason", "")
        if header.lower() == "strict-transport-security":
            if status == "pass":
                if "HSTS set with adequate max-age and preloaded" in reason:
                    header_score += 5
                else:
                    header_score += 0
            else:
                header_score -= 20
        if header.lower() == "content-security-policy":
            if status == "pass":
                if "CSP present and default-src 'none' and form-action restricted" in reason:
                    header_score += 5
                else:
                    header_score += 0
            elif status == "warn":
                header_score -= 20
            else:
                header_score -= 25
        if header.lower() == "x-frame-options":
            if status == "pass":
                header_score += 5
            elif status == "warn":
                header_score += 0
            else:
                header_score -= 20
        if header.lower() == "x-content-type-options":
            if status == "pass":
                header_score += 0
            else:
                header_score -= 5
        if header.lower() == "referrer-policy":
            if status == "pass":
                header_score += 5
            else:
                if "Missing Referrer-Policy" in reason:
                    header_score += 0
                else:
                    header_score -= 5
            
    # Check for insecure values in optional headers
    for header, value in header_findings.items():
        status = value.get("status")
        reason = value.get("reason", "")
        if header.lower() == "x-permitted-cross-domain-policies":
            if status == "pass":
                header_score += 5
        if header.lower() == "cross-origin-resource-policy":
            if status == "pass":
                header_score += 5
        if header.lower() == "cross-origin-embedder-policy":
            if status == "pass":
                header_score += 5
        if header.lower() == "cross-origin-opener-policy":
            if status == "pass":
                header_score += 5
        
    scoring_report["scores"]["headers"] = header_score

    # Score Cookies
    cookie_findings = scan_results.get("cookies", [])
    scoring_report["details"]["cookies"] = cookie_findings
    cookie_score = 0

    scoring_report["scores"]["cookies"] = cookie_score
    
    # Score TLS
    tls_findings = scan_results.get("tls", {})
    scoring_report["details"]["tls"] = tls_findings
    tls_score = 0
    
    scoring_report["scores"]["tls"] = tls_score

    return scoring_report

if __name__ == "__main__":
    # Example usage
    async def run_test():
        test_url = "https://www.google.com/"
        print(f"Scanning URL: {test_url}")
        
        scan_results = await scan_url(test_url)
        scoring_report = score_results(scan_results)
        print("Scoring Report:")
        print(scoring_report)
    
    asyncio.run(run_test())