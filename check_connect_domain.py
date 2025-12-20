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
import datetime
from urllib.parse import urlparse
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
        headers = {
            "accept": "application/json",
            "x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(
            f"{VIRUSTOTAL_BASE_URL}/domains/{domain}",
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json().get("data", {})
            attributes = data.get("attributes", {})
            # with open("check_domain_result.json", "w") as f:
            #     json.dump(attributes, f, indent=4)
            return attributes
            # return {
            #     "domain": domain,
            #     "reputation": attributes.get("reputation"),
            #     "categories": attributes.get("categories"),
            #     "last_analysis_stats": attributes.get("last_analysis_stats"),
            #     "malicious": attributes.get("last_analysis_stats", {}).get("malicious", 0),
            #     "suspicious": attributes.get("last_analysis_stats", {}).get("suspicious", 0),
            #     "harmless": attributes.get("last_analysis_stats", {}).get("harmless", 0),
            #     "undetected": attributes.get("last_analysis_stats", {}).get("undetected", 0),
            #     "creation_date": attributes.get("creation_date"),
            #     "last_update_date": attributes.get("last_update_date"),
            #     "verdict": "MALICIOUS" if attributes.get("last_analysis_stats", {}).get("malicious", 0) > 0 else "CLEAN"
            # }
        elif response.status_code == 404:
            return {"domain": domain, "verdict": "NOT_FOUND", "message": "Domain not found in VirusTotal database"}
        else:
            return {"error": f"VT API error {response.status_code}: {response.text}"}
    except Exception as e:
        return {"error": str(e)}


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

def evaluate_domain_playbook(domain: str):
    """
    Evaluate a domain using 4 criteria:
    1. VirusTotal
    2. Domain name pattern
    3. Google presence (basic heuristic)
    4. HTTP access test
    """
    # print(f"\n=== ĐÁNH GIÁ DOMAIN: {domain} ===")

    # Normalize domain
    parsed = urlparse(domain)
    if parsed.netloc:
        domain = parsed.netloc

    # -----------------------
    # 1. CHECK VIRUSTOTAL
    # -----------------------
    vt_data = virustotal_check_domain(domain)

    score = 0
    details = []

    if "error" in vt_data:
        return {"error": vt_data["error"]}

    malicious = vt_data.get("last_analysis_stats", {}).get("malicious", 0)
    suspicious = vt_data.get("last_analysis_stats", {}).get("suspicious", 0)

    # AV detection count
    if malicious >= 3:
        score += 3
        details.append("[VT] ≥3 AV báo malicious → nghi cao")
    elif 1 <= malicious < 3:
        score += 1
        details.append("[VT] 1–2 AV báo malicious → nghi nhẹ")
    else:
        details.append("[VT] 0 AV báo → khả năng sạch")

    # Creation Date
    creation_ts = vt_data.get("creation_date")
    if creation_ts:
        cd_days = (datetime.datetime.utcnow() - 
                  datetime.datetime.utcfromtimestamp(creation_ts)).days
        if cd_days < 30:
            score += 1
            details.append("[VT] Domain mới <30 ngày → rủi ro cao")
        else:
            details.append("[VT] Domain lâu năm → tăng độ tin cậy")

    # Popular Rank
    if vt_data.get("popularity_ranks"):
        details.append("[VT] Có Popular Rank → tăng uy tín")
    else:
        score += 1
        details.append("[VT] Không có Popular Rank → nghi ngờ")

    # -----------------------------------
    # 2. DOMAIN NAME HEURISTICS
    # -----------------------------------
    suspicious_keywords = ["login", "verify", "secure", "update"]
    if any(k in domain.lower() for k in suspicious_keywords):
        score += 2
        details.append("[NAME] Domain chứa keyword nhạy cảm")

    known_brands = ["google", "facebook", "microsoft", "apple", "amazon", "dantri", "vnexpress"]
    for brand in known_brands:
        if brand in domain.lower() and not domain.lower().startswith(brand):
            score += 3
            details.append("[NAME] Typosquatting theo thương hiệu → nghi cao")

    # -----------------------------------
    # 3. GOOGLE CHECK (HEURISTIC ONLY)
    # -----------------------------------
    # No Google API used → heuristic fallback
    if "." not in domain:
        score += 1
        details.append("[GOOGLE] Domain không hợp lệ → nghi ngờ")
    else:
        details.append("[GOOGLE] Bỏ qua kiểm tra Google API")

    # -----------------------------------
    # 4. HTTP ACCESS TEST
    # -----------------------------------
    try:
        r = requests.get("http://" + domain, timeout=5)
        if r.status_code == 200:
            details.append("[HTTP] Website truy cập được → có thể sạch")
        else:
            score += 1
            details.append("[HTTP] HTTP trả mã lỗi → nghi ngờ")
    except:
        score += 2
        details.append("[HTTP] Không truy cập được → nguy cơ C2/botnet cao")

    # -----------------------------------
    # FINAL DECISION
    # -----------------------------------
    if score >= 6:
        verdict = "MALICIOUS"
    elif 3 <= score < 6:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return {
        "domain": domain,
        "score": score,
        "verdict": verdict,
        "details": details
        # "virustotal_data": vt_data
    }

# print(evaluate_domain_playbook("htlnovx.blogspot.com"))





def evaluate_domain_connection_playbook(domain: str, agent_id: str):
    """
    Đánh giá connect domain theo 4 bước SOC:
    B1: Đánh giá domain độc thật hay không (VirusTotal + heuristics)
    B2: LẤY TẤT CẢ TIẾN TRÌNH truy vấn domain --> đánh giá từng tiến trình
    B3: TẦN SUẤT truy vấn domain trên toàn hệ thống
    B4: Tổng hợp để ra verdict chung
    """

    result = {
        "domain": domain,
        "verdict": None,
        "step1_domain_status": None,
        "step2_process_status": [],
        "step3_log_status": None,
        "decision": None
    }

    # ============================================
    # BƯỚC 1 – VirusTotal
    # ============================================
    vt = evaluate_domain_playbook(domain)

    if "error" in vt:
        result["step1_domain_status"] = f"Lỗi VT: {vt['error']}"
        result["verdict"] = "ESCALATE"
        result["decision"] = "Không đánh giá được VT → Escalate"
        return result

    domain_is_malicious = vt["verdict"] == "MALICIOUS"
    result["step1_domain_status"] = (
        "Domain bị VT đánh dấu độc" if domain_is_malicious 
        else "Domain không bị VT đánh dấu độc"
    )
    
    # ============================================
    # BƯỚC 2 – LẤY TẤT CẢ TIẾN TRÌNH TRUY VẤN DOMAIN
    # ============================================
    query = f'*{domain}* AND agent.id:{agent_id}'
    logs = search_alerts(query, size=200)

    list_process_info = []

    if not logs:
        result["step2_process_status"].append("Không lấy được tiến trình nào trên endpoint")
    else:
        for log in logs:
            proc = log.get("data", {}).get("win", {}).get("eventdata", {})

            process_info = {
                "originalFileName": proc.get("originalFileName"),
                "image": proc.get("image"),
                "commandLine": proc.get("commandLine"),
                "hash": proc.get("hashes"),
                "user": proc.get("user"),
                "parentCommandLine": proc.get("parentCommandLine"),
                "parentImage": proc.get("parentImage"),
                "parentUser": proc.get("parentUser"),
            }

            list_process_info.append(process_info)
            result["step2_process_status"].append(f"{process_info}")

    # ============================================
    # B2 LOGIC – ĐÁNH GIÁ TỪNG TIẾN TRÌNH
    # ============================================
    process_tags = []   # chứa MALICIOUS_PROCESS, BROWSER_QUERY, CLEAN_PROCESS,...

    for proc in list_process_info:
        cmd = (proc.get("commandLine") or "").lower()
        
        if any(b in cmd for b in ["chrome", "brave", "edge", "firefox"]):
            if domain_is_malicious:
                process_tags.append("BROWSER_QUERY_MALICIOUS")
            else:
                process_tags.append("BROWSER_QUERY_CLEAN")
        else:
            if domain_is_malicious:
                process_tags.append("NON_BROWSER_MALICIOUS_PROCESS")
            else:
                process_tags.append("NON_BROWSER_CLEAN_PROCESS")

    if not list_process_info:
        process_tags.append("NO_PROCESS")

    # ============================================
    # BƯỚC 3 – TẦN SUẤT
    # ============================================
    # query_check = f'*{domain}*'
    # print("QUERY FREQ:", query_check)
    freq_logs = search_alerts(f'*{domain}*', size=500)
    device_set = {l.get("agent", {}).get("id") for l in freq_logs}
    query_count = len(freq_logs)

    if len(device_set) > 10:
        result["step3_log_status"] = "Tần suất cao → nghiệp vụ"
        freq_flag = "FP_MASS"
    elif len(device_set) == 1 and query_count > 20:
        result["step3_log_status"] = "1 máy query nhiều lần → nghi nhiễm"
        freq_flag = "SINGLE_INFECTED"
    elif len(device_set) == 1 and 3 <= query_count <= 5:
        result["step3_log_status"] = "1 máy query 3–5 lần → JS embedded"
        freq_flag = "JS_EMBED"
    else:
        result["step3_log_status"] = "Không bất thường"
        freq_flag = "NORMAL"

    # ============================================
    # BƯỚC 4 – TỔNG HỢP QUYẾT ĐỊNH
    # ============================================

    # CASE A: DOMAIN SẠCH
    if not domain_is_malicious:
        result["verdict"] = "FALSE_POSITIVE"

        if freq_flag == "FP_MASS":
            result["decision"] = "Domain sạch → nghiệp vụ"
        elif "BROWSER_QUERY_CLEAN" in process_tags:
            result["decision"] = "Domain sạch → browser query → JS/ads"
        else:
            result["decision"] = "Domain sạch → False Positive"

        return result

    # CASE B: DOMAIN ĐỘC
    if domain_is_malicious:

        if "NON_BROWSER_MALICIOUS_PROCESS" in process_tags:
            result["verdict"] = "MALICIOUS"
            result["decision"] = "Domain độc → tiến trình không phải browser → nghi mã độc"
            return result

        if "BROWSER_QUERY_MALICIOUS" in process_tags:
            result["verdict"] = "MALICIOUS"
            result["decision"] = "Domain độc → query bởi browser → nghi JS/extension/phishing"
            return result

        if "NO_PROCESS" in process_tags:
            result["verdict"] = "ESCALATE"
            result["decision"] = "Domain độc nhưng không lấy được tiến trình"
            return result

    # FALLBACK
    result["verdict"] = "ESCALATE"
    result["decision"] = "Không phân loại được → Escalate"
    return result


res = evaluate_domain_connection_playbook("facebook.com", agent_id="001")
json_output = json.dumps(res, ensure_ascii=False, indent=4)
print(json_output)