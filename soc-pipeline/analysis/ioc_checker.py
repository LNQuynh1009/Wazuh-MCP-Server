#!/usr/bin/env python3

import json
import re
from integrations.virustotal import virustotal_check_ip
from integrations.abuseipdb import abuseipdb_check_ip


def check_alert_iocs(alert_json: str, cache: dict):
    """Extract and check IOCs (IPs) from an alert, using cached results when available."""
    alert_data = json.loads(alert_json) if isinstance(alert_json, str) else alert_json
    alert_str = json.dumps(alert_data)
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = set(re.findall(ip_pattern, alert_str))
    public_ips = []
    for ip in ips:
        if ip.startswith(("10.", "192.168.", "172.", "127.", "0.", "169.254")) or ip == "255.255.255.255":
            continue
        public_ips.append(ip)

    results = {"ips_checked": []}
    for ip in public_ips[:5]:  # small limit
        if ip in cache:
            results["ips_checked"].append({"ip": ip, "cached": True, **cache[ip]})
        else:
            vt = virustotal_check_ip(ip)
            abuse = abuseipdb_check_ip(ip)
            merged = {"vt": vt, "abuse": abuse}
            if (isinstance(vt, dict) and vt.get("verdict") == "MALICIOUS") or (isinstance(abuse, dict) and abuse.get("verdict") == "MALICIOUS"):
                merged["verdict"] = "MALICIOUS"
            elif (isinstance(vt, dict) and vt.get("verdict") == "CLEAN") and (isinstance(abuse, dict) and abuse.get("verdict") == "CLEAN"):
                merged["verdict"] = "CLEAN"
            else:
                merged["verdict"] = "SUSPICIOUS"
            cache[ip] = merged
            results["ips_checked"].append({"ip": ip, **merged})
    return results
