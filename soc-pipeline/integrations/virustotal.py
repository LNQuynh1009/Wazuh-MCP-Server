#!/usr/bin/env python3

import base64
import requests
from config import VIRUSTOTAL_API_KEY, VIRUSTOTAL_BASE_URL


def virustotal_check_ip(ip: str):
    """Check an IP address against VirusTotal."""
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VIRUSTOTAL_API_KEY not configured"}
    headers = {"accept": "application/json", "x-apikey": VIRUSTOTAL_API_KEY}
    try:
        r = requests.get(f"{VIRUSTOTAL_BASE_URL}/ip_addresses/{ip}", headers=headers, timeout=15)
        if r.status_code == 200:
            data = r.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {"ip": ip, "verdict": "MALICIOUS" if stats.get("malicious", 0) > 0 else "CLEAN", "stats": stats}
        else:
            return {"ip": ip, "error": f"VT {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def virustotal_check_file_hash(h: str):
    """Check a file hash against VirusTotal."""
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VIRUSTOTAL_API_KEY not configured"}
    headers = {"accept": "application/json", "x-apikey": VIRUSTOTAL_API_KEY}
    try:
        r = requests.get(f"{VIRUSTOTAL_BASE_URL}/files/{h}", headers=headers, timeout=15)
        if r.status_code == 200:
            data = r.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {"hash": h, "verdict": "MALICIOUS" if stats.get("malicious", 0) > 0 else "CLEAN", "stats": stats}
        else:
            return {"hash": h, "error": f"VT {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def virustotal_check_url_safe(url: str):
    """Check a URL against VirusTotal."""
    if not VIRUSTOTAL_API_KEY:
        return {"url": url, "error": "VIRUSTOTAL_API_KEY not configured"}
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"accept": "application/json", "x-apikey": VIRUSTOTAL_API_KEY}
        r = requests.get(f"{VIRUSTOTAL_BASE_URL}/urls/{url_id}", headers=headers, timeout=15)
        if r.status_code == 200:
            data = r.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {"url": url, "verdict": "MALICIOUS" if stats.get("malicious", 0) > 0 else "CLEAN", "stats": stats}
        else:
            return {"url": url, "error": f"VT {r.status_code}"}
    except Exception as e:
        return {"url": url, "error": str(e)}
