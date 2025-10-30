import os
import requests
import json
import re
import base64
import pandas as pd
from datetime import datetime, timedelta
from fastmcp import FastMCP
from requests.auth import HTTPBasicAuth

# === Load environment variables ===
WAZUH_HOST = os.getenv("WAZUH_HOST", "https://localhost")
WAZUH_PORT = os.getenv("WAZUH_PORT", "55000")
WAZUH_USER = os.getenv("WAZUH_USER", "wazuh-wui")
WAZUH_PASS = os.getenv("WAZUH_PASS", "wazuh-wui")
ALLOW_SELF_SIGNED = os.getenv("WAZUH_ALLOW_SELF_SIGNED", "true").lower() == "true"
VERIFY_SSL = not ALLOW_SELF_SIGNED
BASE_URL = f"{WAZUH_HOST}:{WAZUH_PORT}"

# === Threat Intelligence APIs ===
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"

mcp = FastMCP("opensearch-mcp-server")

# === Helper: Get JWT token ===
def get_wazuh_token():
    url = f"{BASE_URL}/security/user/authenticate"
    resp = requests.get(url, auth=(WAZUH_USER, WAZUH_PASS), verify=VERIFY_SSL)
    if resp.status_code != 200:
        raise Exception(f"Auth failed: {resp.text}")
    return resp.json()["data"]["token"]

# ========== EXISTING WAZUH TOOLS ==========

@mcp.tool()
def ping():
    """Test connection to Wazuh API."""
    try:
        token = get_wazuh_token()
        return {"status": "ok", "token_length": len(token)}
    except Exception as e:
        return {"status": "error", "detail": str(e)}

@mcp.tool()
def list_agents(limit: int = 5):
    """List registered Wazuh agents (default: 5)."""
    try:
        token = get_wazuh_token()
        headers = {"Authorization": f"Bearer {token}"}
        url = f"{BASE_URL}/agents?sort=-ip,name&pretty=true"
        resp = requests.get(url, headers=headers, verify=VERIFY_SSL)
        data = resp.json()
        agents = data.get("data", {}).get("affected_items", [])
        return agents[:limit] if agents else {"message": "No agents found"}
    except Exception as e:
        return {"error": str(e)}

@mcp.tool()
def search_alerts(query: str, size: int = 10):
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
    return hits

# ========== NEW: VIRUSTOTAL TOOLS ==========

@mcp.tool()
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
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(
            f"{VIRUSTOTAL_BASE_URL}/ip_addresses/{ip}",
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json().get("data", {})
            attributes = data.get("attributes", {})
            
            return {
                "ip": ip,
                "country": attributes.get("country"),
                "asn": attributes.get("asn"),
                "as_owner": attributes.get("as_owner"),
                "reputation": attributes.get("reputation"),
                "last_analysis_stats": attributes.get("last_analysis_stats"),
                "malicious": attributes.get("last_analysis_stats", {}).get("malicious", 0),
                "suspicious": attributes.get("last_analysis_stats", {}).get("suspicious", 0),
                "harmless": attributes.get("last_analysis_stats", {}).get("harmless", 0),
                "undetected": attributes.get("last_analysis_stats", {}).get("undetected", 0),
                "verdict": "MALICIOUS" if attributes.get("last_analysis_stats", {}).get("malicious", 0) > 0 else "CLEAN"
            }
        elif response.status_code == 404:
            return {"ip": ip, "verdict": "NOT_FOUND", "message": "IP not found in VirusTotal database"}
        else:
            return {"error": f"VT API error {response.status_code}: {response.text}"}
    except Exception as e:
        return {"error": str(e)}

@mcp.tool()
def virustotal_check_domain(domain: str):
    """Check a domain reputation on VirusTotal.
    
    Args:
        domain: Domain to check (e.g., 'google.com')
    
    Returns:
        Dict with reputation, malicious detections, categories, etc.
    """
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VIRUSTOTAL_API_KEY not set in environment"}
    
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(
            f"{VIRUSTOTAL_BASE_URL}/domains/{domain}",
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json().get("data", {})
            attributes = data.get("attributes", {})
            
            return {
                "domain": domain,
                "reputation": attributes.get("reputation"),
                "categories": attributes.get("categories"),
                "last_analysis_stats": attributes.get("last_analysis_stats"),
                "malicious": attributes.get("last_analysis_stats", {}).get("malicious", 0),
                "suspicious": attributes.get("last_analysis_stats", {}).get("suspicious", 0),
                "harmless": attributes.get("last_analysis_stats", {}).get("harmless", 0),
                "undetected": attributes.get("last_analysis_stats", {}).get("undetected", 0),
                "creation_date": attributes.get("creation_date"),
                "last_update_date": attributes.get("last_update_date"),
                "verdict": "MALICIOUS" if attributes.get("last_analysis_stats", {}).get("malicious", 0) > 0 else "CLEAN"
            }
        elif response.status_code == 404:
            return {"domain": domain, "verdict": "NOT_FOUND", "message": "Domain not found in VirusTotal database"}
        else:
            return {"error": f"VT API error {response.status_code}: {response.text}"}
    except Exception as e:
        return {"error": str(e)}

@mcp.tool()
def virustotal_check_file_hash(file_hash: str):
    """Check a file hash (MD5, SHA1, or SHA256) on VirusTotal.
    
    Args:
        file_hash: File hash to check (MD5/SHA1/SHA256)
    
    Returns:
        Dict with file info, malicious detections, reputation, etc.
    """
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VIRUSTOTAL_API_KEY not set in environment"}
    
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(
            f"{VIRUSTOTAL_BASE_URL}/files/{file_hash}",
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json().get("data", {})
            attributes = data.get("attributes", {})
            
            return {
                "hash": file_hash,
                "file_name": attributes.get("meaningful_name"),
                "file_type": attributes.get("type_description"),
                "size": attributes.get("size"),
                "last_analysis_stats": attributes.get("last_analysis_stats"),
                "malicious": attributes.get("last_analysis_stats", {}).get("malicious", 0),
                "suspicious": attributes.get("last_analysis_stats", {}).get("suspicious", 0),
                "harmless": attributes.get("last_analysis_stats", {}).get("harmless", 0),
                "undetected": attributes.get("last_analysis_stats", {}).get("undetected", 0),
                "reputation": attributes.get("reputation"),
                "first_submission_date": attributes.get("first_submission_date"),
                "last_submission_date": attributes.get("last_submission_date"),
                "verdict": "MALICIOUS" if attributes.get("last_analysis_stats", {}).get("malicious", 0) > 0 else "CLEAN"
            }
        elif response.status_code == 404:
            return {"hash": file_hash, "verdict": "NOT_FOUND", "message": "Hash not found in VirusTotal database"}
        else:
            return {"error": f"VT API error {response.status_code}: {response.text}"}
    except Exception as e:
        return {"error": str(e)}

@mcp.tool()
def virustotal_check_url(url: str):
    """Check a URL reputation on VirusTotal.
    
    Args:
        url: URL to check (e.g., 'https://example.com')
    
    Returns:
        Dict with URL reputation, malicious detections, categories, etc.
    """
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VIRUSTOTAL_API_KEY not set in environment"}
    
    try:
        # VirusTotal uses base64 URL-safe encoding for URL identifiers
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(
            f"{VIRUSTOTAL_BASE_URL}/urls/{url_id}",
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json().get("data", {})
            attributes = data.get("attributes", {})
            
            return {
                "url": url,
                "reputation": attributes.get("reputation"),
                "last_analysis_stats": attributes.get("last_analysis_stats"),
                "malicious": attributes.get("last_analysis_stats", {}).get("malicious", 0),
                "suspicious": attributes.get("last_analysis_stats", {}).get("suspicious", 0),
                "harmless": attributes.get("last_analysis_stats", {}).get("harmless", 0),
                "undetected": attributes.get("last_analysis_stats", {}).get("undetected", 0),
                "categories": attributes.get("categories"),
                "last_submission_date": attributes.get("last_submission_date"),
                "verdict": "MALICIOUS" if attributes.get("last_analysis_stats", {}).get("malicious", 0) > 0 else "CLEAN"
            }
        elif response.status_code == 404:
            return {"url": url, "verdict": "NOT_FOUND", "message": "URL not found in VirusTotal database"}
        else:
            return {"error": f"VT API error {response.status_code}: {response.text}"}
    except Exception as e:
        return {"error": str(e)}

# ========== NEW: ABUSEIPDB TOOL ==========

@mcp.tool()
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
            
            abuse_score = data.get("abuseConfidenceScore", 0)
            verdict = "CLEAN"
            if abuse_score > 75:
                verdict = "MALICIOUS"
            elif abuse_score > 25:
                verdict = "SUSPICIOUS"
            
            return {
                "ip": ip,
                "abuse_confidence_score": abuse_score,
                "country": data.get("countryCode"),
                "usage_type": data.get("usageType"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "is_whitelisted": data.get("isWhitelisted"),
                "total_reports": data.get("totalReports"),
                "num_distinct_users": data.get("numDistinctUsers"),
                "last_reported_at": data.get("lastReportedAt"),
                "verdict": verdict
            }
        else:
            return {"error": f"AbuseIPDB API error {response.status_code}: {response.text}"}
    except Exception as e:
        return {"error": str(e)}

# ========== NEW: BULK IOC CHECKER ==========

@mcp.tool()
def check_alert_iocs(alert_json: str):
    """Extract and check all IOCs (IPs, domains, hashes) from Wazuh alert data.
    
    Args:
        alert_json: JSON string of alert data from search_alerts
    
    Returns:
        Dict with checked IPs, domains, and hashes with their threat intel results
    """
    try:
        # Parse alert data
        if isinstance(alert_json, str):
            alert_data = json.loads(alert_json)
        else:
            alert_data = alert_json
        
        results = {
            "summary": {
                "total_ips_found": 0,
                "public_ips_checked": 0,
                "malicious_ips": 0,
                "suspicious_ips": 0
            },
            "ips_checked": []
        }
        
        # Convert alert data to string for regex extraction
        alert_str = json.dumps(alert_data)
        
        # Extract IPs using regex
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = set(re.findall(ip_pattern, alert_str))
        results["summary"]["total_ips_found"] = len(ips)
        
        # Filter out private IPs
        private_ip_patterns = [
            r'^10\.',
            r'^172\.(1[6-9]|2[0-9]|3[01])\.',
            r'^192\.168\.',
            r'^127\.',
            r'^0\.',
            r'^169\.254\.',
            r'^255\.'
        ]
        
        public_ips = []
        for ip in ips:
            is_private = any(re.match(pattern, ip) for pattern in private_ip_patterns)
            if not is_private and ip != "0.0.0.0":
                public_ips.append(ip)
        
        # Check public IPs (limit to 5 to avoid rate limits)
        for ip in list(public_ips)[:5]:
            vt_result = virustotal_check_ip(ip)
            abuse_result = abuseipdb_check_ip(ip)
            
            combined_verdict = "CLEAN"
            if vt_result.get("verdict") == "MALICIOUS" or abuse_result.get("verdict") == "MALICIOUS":
                combined_verdict = "MALICIOUS"
                results["summary"]["malicious_ips"] += 1
            elif vt_result.get("verdict") == "SUSPICIOUS" or abuse_result.get("verdict") == "SUSPICIOUS":
                combined_verdict = "SUSPICIOUS"
                results["summary"]["suspicious_ips"] += 1
            
            results["ips_checked"].append({
                "ip": ip,
                "verdict": combined_verdict,
                "virustotal": vt_result,
                "abuseipdb": abuse_result
            })
            results["summary"]["public_ips_checked"] += 1
        
        return results
    except Exception as e:
        return {"error": str(e)}

# ========== ALERT CLASSIFICATION HELPERS (Based on Playbook) ==========

def classify_phishing(alert):
    desc = alert.get("rule", {}).get("description", "").lower()
    url = alert.get("data", {}).get("url") or alert.get("url")
    verdict = "FP"
    reason = "No malicious URL found"

    if url:
        vt = virustotal_check_url(url)
        if vt.get("verdict") == "MALICIOUS":
            verdict = "TP"
            reason = f"Malicious URL detected ({url}) per VirusTotal"
    elif "phishing" in desc or "email" in desc:
        verdict = "TP"
        reason = "Phishing-related rule triggered"
    
    return {"category": "phishing", "classification": verdict, "reason": reason}


def classify_malware(alert):
    desc = alert.get("rule", {}).get("description", "").lower()
    file_hash = alert.get("data", {}).get("md5") or alert.get("data", {}).get("sha256")
    verdict = "FP"
    reason = "No malicious file found"

    if file_hash:
        vt = virustotal_check_file_hash(file_hash)
        if vt.get("verdict") == "MALICIOUS":
            verdict = "TP"
            reason = f"Malicious file hash {file_hash}"
    elif "malware" in desc or "trojan" in desc or "ransom" in desc:
        verdict = "TP"
        reason = "Malware keyword detected in rule description"
    
    return {"category": "malware", "classification": verdict, "reason": reason}


def classify_ip_connection(alert):
    src_ip = alert.get("srcip")
    verdict = "FP"
    reason = "No public malicious IP"

    if src_ip:
        intel = check_alert_iocs(json.dumps(alert))
        if intel.get("summary", {}).get("malicious_ips", 0) > 0:
            verdict = "TP"
            reason = f"Connection to malicious IP {src_ip}"
    
    return {"category": "ip_connection", "classification": verdict, "reason": reason}


def classify_web_attack(alert):
    desc = alert.get("rule", {}).get("description", "").lower()
    verdict = "FP"
    reason = "No exploit indicators found"

    keywords = ["xss", "sql injection", "rce", "directory traversal", "webshell"]
    if any(k in desc for k in keywords):
        verdict = "TP"
        reason = f"Web attack pattern detected: {desc}"
    
    return {"category": "web_attack", "classification": verdict, "reason": reason}


def classify_bruteforce(alert):
    desc = alert.get("rule", {}).get("description", "").lower()
    verdict = "FP"
    reason = "No repeated authentication attempts"

    if "brute" in desc or "login failed" in desc:
        verdict = "TP"
        reason = "Detected brute-force pattern"
    
    return {"category": "bruteforce", "classification": verdict, "reason": reason}


def classify_login_anomaly(alert):
    desc = alert.get("rule", {}).get("description", "").lower()
    verdict = "FP"
    reason = "Normal login activity"

    if "login" in desc and "unusual" in desc:
        verdict = "TP"
        reason = "Detected login from abnormal IP or region"
    
    return {"category": "login_anomaly", "classification": verdict, "reason": reason}

# ========== CLASSIFY AND THEN EXPORT IT TO EXCEL (Based on Playbook) ==========

@mcp.tool()
def classify_and_export_alerts():
    """Fetch last 24h Wazuh alerts, classify as TP/FP, and export TPs to Excel."""
    try:
        host = os.getenv("OPENSEARCH_HOST")
        port = os.getenv("OPENSEARCH_PORT", "9200")
        user = os.getenv("OPENSEARCH_USER")
        password = os.getenv("OPENSEARCH_PASS")
        verify_ssl = os.getenv("OPENSEARCH_SSL_VERIFY", "true").lower() == "true"

        # --- Step 1: Build 24h time range query ---
        now = datetime.utcnow()
        last_24h = now - timedelta(hours=24)

        query = {
            "size": 1000,  # limit results for demo; adjust as needed
            "query": {
                "range": {
                    "@timestamp": {
                        "gte": last_24h.strftime("%Y-%m-%dT%H:%M:%S"),
                        "lte": now.strftime("%Y-%m-%dT%H:%M:%S"),
                        "format": "strict_date_optional_time"
                    }
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}]
        }

        url = f"{host}:{port}/wazuh-alerts-*/_search"
        response = requests.get(url, auth=HTTPBasicAuth(user, password), json=query, verify=verify_ssl)
        if response.status_code != 200:
            return {"error": f"OpenSearch query failed: {response.text}"}

        alerts = [hit["_source"] for hit in response.json().get("hits", {}).get("hits", [])]

        if not alerts:
            return {"message": "No alerts found in the last 24 hours."}

        # --- Step 2: Classify alerts ---
        classified_alerts = []
        tp_alerts = []

        for alert in alerts:
            desc = alert.get("rule", {}).get("description", "").lower()
            classification = {"category": "general", "classification": "FP", "reason": "Unclassified"}

            # Identify alert type from playbook categories
            if "phish" in desc or "email" in desc:
                classification = classify_phishing(alert)
            elif "malware" in desc or "trojan" in desc or "ransom" in desc:
                classification = classify_malware(alert)
            elif "ip" in desc or "domain" in desc:
                classification = classify_ip_connection(alert)
            elif "web" in desc or "sql" in desc or "xss" in desc:
                classification = classify_web_attack(alert)
            elif "brute" in desc or "password" in desc:
                classification = classify_bruteforce(alert)
            elif "login" in desc or "user" in desc:
                classification = classify_login_anomaly(alert)

            alert.update(classification)

            classified_alerts.append(alert)
            if classification["classification"] == "TP":
                tp_alerts.append(alert)

        # --- Step 3: Export TP alerts to Excel ---
        if tp_alerts:
            df = pd.DataFrame(tp_alerts)
            output_file = f"true_positive_alerts_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.xlsx"
            df.to_excel(output_file, index=False)
        else:
            output_file = None

        # --- Step 4: Return summary ---
        summary = {
            "total_alerts": len(alerts),
            "true_positives": len(tp_alerts),
            "false_positives": len(alerts) - len(tp_alerts),
            "exported_file": output_file or "No TPs found"
        }

        return summary

    except Exception as e:
        return {"error": str(e)}


if __name__ == "__main__":
    print(f"Starting Wazuh MCP server on {BASE_URL}...")
    print(f"VirusTotal API: {'Configured' if VIRUSTOTAL_API_KEY else 'Not configured'}")
    print(f"AbuseIPDB API: {'Configured' if ABUSEIPDB_API_KEY else 'Not configured'}")
    mcp.run()
