#!/usr/bin/env python3

import base64
import aiohttp
from config import VIRUSTOTAL_API_KEY, VIRUSTOTAL_BASE_URL


async def async_virustotal_check_ip(ip: str, session: aiohttp.ClientSession):
    """Check an IP address against VirusTotal (async)."""
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VIRUSTOTAL_API_KEY not configured"}
    headers = {"accept": "application/json", "x-apikey": VIRUSTOTAL_API_KEY}
    try:
        async with session.get(
            f"{VIRUSTOTAL_BASE_URL}/ip_addresses/{ip}",
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=15)
        ) as r:
            if r.status == 200:
                data = await r.json()
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                return {
                    "ip": ip,
                    "verdict": "MALICIOUS" if stats.get("malicious", 0) > 0 else "CLEAN",
                    "stats": stats
                }
            else:
                return {"ip": ip, "error": f"VT {r.status}"}
    except Exception as e:
        return {"error": str(e)}


async def async_virustotal_check_file_hash(h: str, session: aiohttp.ClientSession):
    """Check a file hash against VirusTotal (async)."""
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VIRUSTOTAL_API_KEY not configured"}
    headers = {"accept": "application/json", "x-apikey": VIRUSTOTAL_API_KEY}
    try:
        async with session.get(
            f"{VIRUSTOTAL_BASE_URL}/files/{h}",
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=15)
        ) as r:
            if r.status == 200:
                data = await r.json()
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                return {
                    "hash": h,
                    "verdict": "MALICIOUS" if stats.get("malicious", 0) > 0 else "CLEAN",
                    "stats": stats
                }
            else:
                return {"hash": h, "error": f"VT {r.status}"}
    except Exception as e:
        return {"error": str(e)}


async def async_virustotal_check_url_safe(url: str, session: aiohttp.ClientSession):
    """Check a URL against VirusTotal (async)."""
    if not VIRUSTOTAL_API_KEY:
        return {"url": url, "error": "VIRUSTOTAL_API_KEY not configured"}
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"accept": "application/json", "x-apikey": VIRUSTOTAL_API_KEY}
        async with session.get(
            f"{VIRUSTOTAL_BASE_URL}/urls/{url_id}",
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=15)
        ) as r:
            if r.status == 200:
                data = await r.json()
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                return {
                    "url": url,
                    "verdict": "MALICIOUS" if stats.get("malicious", 0) > 0 else "CLEAN",
                    "stats": stats
                }
            else:
                return {"url": url, "error": f"VT {r.status}"}
    except Exception as e:
        return {"url": url, "error": str(e)}
