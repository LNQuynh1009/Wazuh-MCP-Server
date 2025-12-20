from dotenv import load_dotenv
import os

import os
import requests
import json
import re
import base64
from fastmcp import FastMCP
from requests.auth import HTTPBasicAuth

from dotenv import load_dotenv
import os

# === Load environment variables from file env===
load_dotenv()

WAZUH_HOST = os.getenv("WAZUH_HOST")
WAZUH_PORT = os.getenv("WAZUH_PORT")
WAZUH_USER = os.getenv("WAZUH_USER")
WAZUH_PASS = os.getenv("WAZUH_PASS")
ALLOW_SELF_SIGNED = os.getenv("WAZUH_ALLOW_SELF_SIGNED", "true").lower() == "true"
VERIFY_SSL = not ALLOW_SELF_SIGNED
BASE_URL = f"{WAZUH_HOST}:{WAZUH_PORT}"

# === Threat Intelligence APIs ===
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"
IP2LOCATION_API_KEY = os.getenv("IP2LOCATION_API_KEY")

def virustotal_check_ip(ip: str):
    """Check an IP address reputation on VirusTotal.
    
    Args:
        ip: IP address to check (e.g., '8.8.8.8')
    
    Returns:
        Dict with reputation, malicious detections, country, ASN, etc.
    """
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VIRUSTOTAL_API_KEY not set in environment"}
    
    try:
        headers = {
            "accept": "application/json",
            "x-apikey": VIRUSTOTAL_API_KEY
            }
        response = requests.get(
            f"{VIRUSTOTAL_BASE_URL}/ip_addresses/{ip}",
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json().get("data", {})
            attributes = data.get("attributes", {})
            return attributes

        elif response.status_code == 404:
            return {"ip": ip, "verdict": "NOT_FOUND", "message": "IP not found in VirusTotal database"}
        else:
            return {"error": f"VT API error {response.status_code}: {response.text}"}
    except Exception as e:
        return {"error": str(e)}
def abuseipdb_check_ip(ip: str):
    """Check IP reputation on AbuseIPDB.
    
    Args:
        ip: IP address to check (e.g., '1.2.3.4')
    
    Returns:
        Dict with abuse confidence score, reports, country, ISP, etc.
    """
    if not ABUSEIPDB_API_KEY:
        return {"error": "ABUSEIPDB_API_KEY not set in environment"}
    
    try:
        headers = {
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": ""
        }
        
        response = requests.get(
            f"{ABUSEIPDB_BASE_URL}/check",
            headers=headers,
            params=params
        )
        
        if response.status_code == 200:
            data = response.json().get("data", {})
            with open("abuseipdb_response.json", "w") as f:
                json.dump(data, f, indent=4)
            return data
        else:
            return {"error": f"AbuseIPDB API error {response.status_code}: {response.text}"}
    except Exception as e:
        return {"error": str(e)}

def check_ip2location(ip: str):
    """Check IP geolocation using ip2location 
    Args:
        ip: IP address to check (e.g., '
    """
    try:
        # print(IP2LOCATION_API_KEY)
        response = requests.get(f"https://api.ip2location.io/?key={IP2LOCATION_API_KEY}&ip={ip}&format=json")
        if response.status_code == 200:
            data = response.json()
            with open("ip2location_response.json", "w") as f:
                json.dump(data, f, indent=4)
            return data
        else:
            return {"error": f"ip2location API error {response.status_code}: {response.text}"}
    except Exception as e:
        return {"error": str(e)}
    
def check_ip_vpn(ip: str):
    """
    Check if an IP is a VPN/proxy using ip2location proxy addon
    Args:
        ip: IP address to check (e.g., '
    """

    url = f"https://api.ip2location.io/?key={IP2LOCATION_API_KEY}&ip={ip}&addon=all"
    resp = requests.get(url, timeout=5)
    resp.raise_for_status()
    data = resp.json()
    # kiểm tra trường proxy
    proxy_info = data.get("proxy", {})
    is_vpn = proxy_info.get("is_vpn", False)
    return {
        "ip": ip,
        "is_vpn": is_vpn,
        "proxy_type": proxy_info.get("proxy_type"),
        "full_info": data
    }

def search_alerts(query: str, size: int = 100):
    """Run a search query directly against the OpenSearch Wazuh alert indices."""
    host = os.getenv("OPENSEARCH_HOST")
    port = os.getenv("OPENSEARCH_PORT", "9200")
    user = os.getenv("OPENSEARCH_USER")
    password = os.getenv("OPENSEARCH_PASS")
    verify_ssl = os.getenv("OPENSEARCH_SSL_VERIFY", "true").lower() == "true"
    
    url = f"{host}:{port}/wazuh-alerts-*/_search"
    payload = {
        "size": size,
        "query": {
            "query_string": {
                "query": query
            }
        },
        "sort": [{"@timestamp": {"order": "desc"}}]
    }
    
    response = requests.get(url, auth=HTTPBasicAuth(user, password), json=payload, verify=verify_ssl)
    if response.status_code != 200:
        return {"error": response.text}
    
    data = response.json()
    hits = [hit["_source"] for hit in data.get("hits", {}).get("hits", [])]
    # print(hits)
    return hits



def evaluate_ip_threat(ip: str):
    """Đánh giá IP theo playbook, chỉ trả về kết quả các tiêu chí (không chứa raw data)."""

    result = {
        "ip": ip,
        "criteria": {
            "domain_resolution": None,
            "virustotal": {},
            "crowdsource": None,
            "relations": None,
            "abuseipdb": {},
            "ip2location": {},
            "vpn_check": None
        },
        "verdict": "UNKNOWN",
        "reason": []
    }

    # ======================================================
    # 0) DOMAIN RESOLUTION (Ưu tiên cao nhất)
    # ======================================================
    vt = virustotal_check_ip(ip)
    vt_attr = vt if isinstance(vt, dict) else {}

    vt_dns = vt_attr.get("last_dns_records", [])
    resolved_domains = [d.get("value") for d in vt_dns if d.get("value")]

    if len(resolved_domains) > 100:
        # nhiều domain con → hosting
        roots = {dom.split(".")[-2:] for dom in resolved_domains if "." in dom}
        if len(roots) > 10:
            result["criteria"]["domain_resolution"] = "hosting"
            result["verdict"] = "CLEAN"
            result["reason"].append("IP resolve > 100 domain khác nhau → hosting → sạch.")
            return result
    else:
        result["criteria"]["domain_resolution"] = "normal"

    # ======================================================
    # 1) VIRUSTOTAL
    # ======================================================
    stats = vt_attr.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    community_score = vt_attr.get("reputation", 0)

    vt_result = "clean"
    if malicious >= 3:
        vt_result = "malicious"
    elif 0 < malicious < 3:
        vt_result = "low_suspicious"

    result["criteria"]["virustotal"] = {
        "malicious_av": malicious,
        "community_score": community_score,
        "result": vt_result
    }

    # ======================================================
    # 2) CROWDSOURCE
    # ======================================================
    if vt_attr.get("crowdsourced_context"):
        result["criteria"]["crowdsource"] = "has_context"
    else:
        result["criteria"]["crowdsource"] = "no_context"

    # ======================================================
    # 3) RELATIONS
    # ======================================================
    relations = vt_attr.get("last_analysis_results", {})
    malicious_engines = [
        e for e, d in relations.items() if d.get("category") == "malicious"
    ]

    if len(malicious_engines) > 5:
        result["criteria"]["relations"] = "many_malicious_relations"
    elif len(malicious_engines) > 0:
        result["criteria"]["relations"] = "some_malicious_relations"
    else:
        result["criteria"]["relations"] = "clean_relations"

    # ======================================================
    # 4) ABUSEIPDB
    # ======================================================
    abuse = abuseipdb_check_ip(ip)
    if isinstance(abuse, dict):
        score = abuse.get("abuseConfidenceScore", 0)
        if score > 75:
            result["criteria"]["abuseipdb"] = {"score": score, "result": "malicious"}
        elif score > 25:
            result["criteria"]["abuseipdb"] = {"score": score, "result": "suspicious"}
        else:
            result["criteria"]["abuseipdb"] = {"score": score, "result": "clean"}
    else:
        result["criteria"]["abuseipdb"] = {"score": None, "result": "unknown"}

    # ======================================================
    # 5) IP2LOCATION — ISP / COUNTRY
    # ======================================================
    ip2 = check_ip2location(ip)
    country = ip2.get("country_code", None)
    isp = ip2.get("isp", "").lower()

    isp_status = "unknown"
    if any(x in isp for x in ["google", "microsoft", "amazon", "akamai", "cloudflare"]):
        isp_status = "high_trust"
    elif "viettel" in isp or "vnpt" in isp or "fpt" in isp:
        isp_status = "vn_local"

    result["criteria"]["ip2location"] = {
        "country": country,
        "isp_reputation": isp_status
    }

    # ======================================================
    # 6) VPN / Proxy check
    # ======================================================
    vpn_info = check_ip_vpn(ip)
    if vpn_info.get("is_vpn"):
        result["criteria"]["vpn_check"] = "vpn"
    else:
        result["criteria"]["vpn_check"] = "not_vpn"

    # ======================================================
    # FINAL VERDICT
    # ======================================================

    # ---- Playbook Rules ----
    if country == "VN":
        result["reason"].append("IP thuộc Việt Nam → không tác động nếu không có bằng chứng mạnh.")

    if result["criteria"]["virustotal"]["result"] == "malicious":
        result["verdict"] = "MALICIOUS"
        result["reason"].append(">= 3 AV phát hiện độc.")

    elif result["criteria"]["abuseipdb"]["result"] == "malicious":
        result["verdict"] = "MALICIOUS"
        result["reason"].append("AbuseIPDB score > 75.")

    elif result["criteria"]["vpn_check"] == "vpn":
        result["verdict"] = "SUSPICIOUS"
        result["reason"].append("IP là VPN.")

    elif result["criteria"]["virustotal"]["result"] == "low_suspicious":
        result["verdict"] = "SUSPICIOUS"
        result["reason"].append("Có AV báo nhưng ít.")

    elif result["criteria"]["virustotal"]["result"] == "clean" and \
         result["criteria"]["abuseipdb"]["result"] == "clean" and \
         result["criteria"]["vpn_check"] == "not_vpn":
        result["verdict"] = "CLEAN"
        result["reason"].append("Không có dấu hiệu độc hại.")

    else:
        result["verdict"] = "SUSPICIOUS"
        result["reason"].append("Không đủ bằng chứng để kết luận.")

    return result
print(evaluate_ip_threat("52.123.129.14"))
 
# print(abuseipdb_check_ip("111.243.135.27"))
    

    
