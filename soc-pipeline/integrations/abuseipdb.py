#!/usr/bin/env python3

import requests
from config import ABUSEIPDB_API_KEY, ABUSEIPDB_BASE_URL


def abuseipdb_check_ip(ip: str):
    """Check an IP address against AbuseIPDB."""
    if not ABUSEIPDB_API_KEY:
        return {"error": "ABUSEIPDB_API_KEY not configured"}
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        r = requests.get(f"{ABUSEIPDB_BASE_URL}/check", headers=headers, params=params, timeout=15)
        if r.status_code == 200:
            d = r.json().get("data", {})
            score = d.get("abuseConfidenceScore", 0)
            verdict = "MALICIOUS" if score > 75 else "SUSPICIOUS" if score > 25 else "CLEAN"
            return {"ip": ip, "verdict": verdict, "score": score}
        else:
            return {"ip": ip, "error": f"AbuseIPDB {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}
