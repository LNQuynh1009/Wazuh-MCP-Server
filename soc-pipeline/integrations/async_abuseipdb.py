#!/usr/bin/env python3

import aiohttp
from config import ABUSEIPDB_API_KEY, ABUSEIPDB_BASE_URL


async def async_abuseipdb_check_ip(ip: str, session: aiohttp.ClientSession):
    """Check an IP address against AbuseIPDB (async)."""
    if not ABUSEIPDB_API_KEY:
        return {"error": "ABUSEIPDB_API_KEY not configured"}
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        async with session.get(
            f"{ABUSEIPDB_BASE_URL}/check",
            headers=headers,
            params=params,
            timeout=aiohttp.ClientTimeout(total=15)
        ) as r:
            if r.status == 200:
                data = await r.json()
                d = data.get("data", {})
                score = d.get("abuseConfidenceScore", 0)
                verdict = "MALICIOUS" if score > 75 else "SUSPICIOUS" if score > 25 else "CLEAN"
                return {"ip": ip, "verdict": verdict, "score": score}
            else:
                return {"ip": ip, "error": f"AbuseIPDB {r.status}"}
    except Exception as e:
        return {"error": str(e)}
