#!/usr/bin/env python3

import json
import re
import asyncio
import aiohttp
from integrations.async_virustotal import async_virustotal_check_ip
from integrations.async_abuseipdb import async_abuseipdb_check_ip


async def async_check_alert_iocs(alert_json: str, cache: dict, session: aiohttp.ClientSession):
    """Extract and check IOCs (IPs) from an alert, using cached results when available (async)."""
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
    
    # Process IPs with concurrent API calls
    tasks = []
    ips_to_check = []
    
    for ip in public_ips[:5]:  # small limit
        if ip in cache:
            results["ips_checked"].append({"ip": ip, "cached": True, **cache[ip]})
        else:
            ips_to_check.append(ip)
            # Create concurrent tasks for VT + AbuseIPDB
            tasks.append(async_virustotal_check_ip(ip, session))
            tasks.append(async_abuseipdb_check_ip(ip, session))
    
    # Run all API calls concurrently
    if tasks:
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process responses in pairs (VT, Abuse) for each IP
        for i, ip in enumerate(ips_to_check):
            vt_idx = i * 2
            abuse_idx = i * 2 + 1
            
            vt = responses[vt_idx] if vt_idx < len(responses) and not isinstance(responses[vt_idx], Exception) else {"error": "VT failed"}
            abuse = responses[abuse_idx] if abuse_idx < len(responses) and not isinstance(responses[abuse_idx], Exception) else {"error": "Abuse failed"}
            
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
