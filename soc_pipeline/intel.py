import base64
import json
import re
import requests
from . import config


def virustotal_check_ip(ip: str):
    if not config.VIRUSTOTAL_API_KEY:
        return {"error": "VIRUSTOTAL_API_KEY not configured"}
    headers = {"accept": "application/json", "x-apikey": config.VIRUSTOTAL_API_KEY}
    try:
        r = requests.get(f"{config.VIRUSTOTAL_BASE_URL}/ip_addresses/{ip}", headers=headers, timeout=15)
        if r.status_code == 200:
            data = r.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {"ip": ip, "verdict": "MALICIOUS" if stats.get("malicious", 0) > 0 else "CLEAN", "stats": stats}
        else:
            return {"ip": ip, "error": f"VT {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def virustotal_check_file_hash(h: str):
    if not config.VIRUSTOTAL_API_KEY:
        return {"error": "VIRUSTOTAL_API_KEY not configured"}
    headers = {"accept": "application/json", "x-apikey": config.VIRUSTOTAL_API_KEY}
    try:
        r = requests.get(f"{config.VIRUSTOTAL_BASE_URL}/files/{h}", headers=headers, timeout=15)
        if r.status_code == 200:
            data = r.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {"hash": h, "verdict": "MALICIOUS" if stats.get("malicious", 0) > 0 else "CLEAN", "stats": stats}
        else:
            return {"hash": h, "error": f"VT {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def virustotal_check_url_safe(url: str):
    if not config.VIRUSTOTAL_API_KEY:
        return {"url": url, "error": "VIRUSTOTAL_API_KEY not configured"}
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"accept": "application/json", "x-apikey": config.VIRUSTOTAL_API_KEY}
        r = requests.get(f"{config.VIRUSTOTAL_BASE_URL}/urls/{url_id}", headers=headers, timeout=15)
        if r.status_code == 200:
            data = r.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {"url": url, "verdict": "MALICIOUS" if stats.get("malicious", 0) > 0 else "CLEAN", "stats": stats}
        else:
            return {"url": url, "error": f"VT {r.status_code}"}
    except Exception as e:
        return {"url": url, "error": str(e)}


def abuseipdb_check_ip(ip: str):
    if not config.ABUSEIPDB_API_KEY:
        return {"error": "ABUSEIPDB_API_KEY not configured"}
    headers = {"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        r = requests.get(f"{config.ABUSEIPDB_BASE_URL}/check", headers=headers, params=params, timeout=15)
        if r.status_code == 200:
            d = r.json().get("data", {})
            score = d.get("abuseConfidenceScore", 0)
            verdict = "MALICIOUS" if score > 75 else "SUSPICIOUS" if score > 25 else "CLEAN"
            return {"ip": ip, "verdict": verdict, "score": score}
        else:
            return {"ip": ip, "error": f"AbuseIPDB {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def check_alert_iocs(alert_json, cache: dict):
    alert_data = json.loads(alert_json) if isinstance(alert_json, str) else alert_json
    alert_str = json.dumps(alert_data)
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    ips = set(re.findall(ip_pattern, alert_str))
    public_ips = []
    for ip in ips:
        if ip.startswith(("10.", "192.168.", "172.", "127.", "0.", "169.254")) or ip == "255.255.255.255":
            continue
        public_ips.append(ip)

    results = {"ips_checked": []}
    for ip in public_ips[:5]:
        if ip in cache:
            results["ips_checked"].append({"ip": ip, "cached": True, **cache[ip]})
        else:
            vt = virustotal_check_ip(ip)
            abuse = abuseipdb_check_ip(ip)
            merged = {"vt": vt, "abuse": abuse}
            if (isinstance(vt, dict) and vt.get("verdict") == "MALICIOUS") or (
                isinstance(abuse, dict) and abuse.get("verdict") == "MALICIOUS"
            ):
                merged["verdict"] = "MALICIOUS"
            elif (isinstance(vt, dict) and vt.get("verdict") == "CLEAN") and (
                isinstance(abuse, dict) and abuse.get("verdict") == "CLEAN"
            ):
                merged["verdict"] = "CLEAN"
            else:
                merged["verdict"] = "SUSPICIOUS"
            cache[ip] = merged
            results["ips_checked"].append({"ip": ip, **merged})
    return results
