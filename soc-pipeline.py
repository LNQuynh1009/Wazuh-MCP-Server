#!/usr/bin/env python3
import os
import time
import json
import re
import base64
import requests
from datetime import datetime, timedelta
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv

# Load .env from current working directory
load_dotenv()

# Optional: Anthropic client
try:
    from anthropic import Anthropic
except Exception:
    Anthropic = None

# ========== Configuration (from env) ==========
WAZUH_HOST = os.getenv("WAZUH_HOST", "https://localhost")
WAZUH_PORT = os.getenv("WAZUH_PORT", "55000")
WAZUH_USER = os.getenv("WAZUH_USER", "wazuh-wui")
WAZUH_PASS = os.getenv("WAZUH_PASS", "wazuh-wui")
ALLOW_SELF_SIGNED = os.getenv("WAZUH_ALLOW_SELF_SIGNED", "true").lower() == "true"
BASE_URL = f"{WAZUH_HOST}:{WAZUH_PORT}"

OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "http://127.0.0.1")
OPENSEARCH_PORT = os.getenv("OPENSEARCH_PORT", "9200")
OPENSEARCH_USER = os.getenv("OPENSEARCH_USER")
OPENSEARCH_PASS = os.getenv("OPENSEARCH_PASS")
OPENSEARCH_VERIFY = os.getenv("OPENSEARCH_SSL_VERIFY", "false").lower() == "true"

# Threat intel
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"

# Claude / Anthropic
# Support both names: CLAUDE_API_KEY or ANTHROPIC_API_KEY
CLAUDE_API_KEY = os.getenv("CLAUDE_API_KEY") or os.getenv("ANTHROPIC_API_KEY")
CLAUDE_MODEL = os.getenv("CLAUDE_MODEL", "claude-sonnet-4-5")

# TheHive
THEHIVE_URL = os.getenv("THEHIVE_URL")
THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY")
THEHIVE_VERIFY_SSL = os.getenv("THEHIVE_VERIFY_SSL", "false").lower() == "true"

# Pipeline tuning
POLL_INTERVAL_SECONDS = int(os.getenv("POLL_INTERVAL_SECONDS", "30"))
MAX_FETCH = int(os.getenv("MAX_FETCH", "500"))

# Persist files
LAST_TS_FILE = os.getenv("LAST_TS_FILE", "last_ts.txt")
IOC_CACHE_FILE = os.getenv("IOC_CACHE_FILE", "ioc_cache.json")

# ========== Helpers: persistent state ==========
def load_last_timestamp():
    try:
        with open(LAST_TS_FILE, "r") as f:
            ts = f.read().strip()
            if ts:
                return ts
    except FileNotFoundError:
        pass
    # default to very recent time to avoid large historical pulls
    return (datetime.utcnow() - timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

def save_last_timestamp(ts):
    try:
        with open(LAST_TS_FILE, "w") as f:
            f.write(ts)
    except Exception:
        pass

def load_ioc_cache():
    try:
        with open(IOC_CACHE_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}

def save_ioc_cache(cache):
    try:
        with open(IOC_CACHE_FILE, "w") as f:
            json.dump(cache, f)
    except Exception:
        pass

# ========== OpenSearch / Wazuh helpers ==========
def fetch_alerts_since(ts: str, size: int = 500):
    """Fetch alerts with @timestamp > ts in ascending order."""
    base = OPENSEARCH_HOST.rstrip("/")
    url = f"{base}:{OPENSEARCH_PORT}/wazuh-alerts-*/_search"
    query = {
        "size": size,
        "query": {"range": {"@timestamp": {"gt": ts}}},
        "sort": [{"@timestamp": {"order": "asc"}}]
    }
    resp = requests.get(url, auth=HTTPBasicAuth(OPENSEARCH_USER, OPENSEARCH_PASS), json=query, verify=OPENSEARCH_VERIFY, timeout=30)
    if resp.status_code != 200:
        raise Exception(f"OpenSearch query failed: {resp.status_code} {resp.text}")
    hits = resp.json().get("hits", {}).get("hits", [])
    return [h["_source"] for h in hits]

# ========== Threat intel helpers ==========
def virustotal_check_ip(ip: str):
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VIRUSTOTAL_API_KEY not configured"}
    headers = {"accept": "application/json", "x-apikey": VIRUSTOTAL_API_KEY}
    try:
        r = requests.get(f"{VIRUSTOTAL_BASE_URL}/ip_addresses/{ip}", headers=headers, timeout=15)
        if r.status_code == 200:
            data = r.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {"ip": ip, "verdict": "MALICIOUS" if stats.get("malicious",0)>0 else "CLEAN", "stats": stats}
        else:
            return {"ip": ip, "error": f"VT {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def virustotal_check_file_hash(h: str):
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VIRUSTOTAL_API_KEY not configured"}
    headers = {"accept": "application/json", "x-apikey": VIRUSTOTAL_API_KEY}
    try:
        r = requests.get(f"{VIRUSTOTAL_BASE_URL}/files/{h}", headers=headers, timeout=15)
        if r.status_code == 200:
            data = r.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {"hash": h, "verdict": "MALICIOUS" if stats.get("malicious",0)>0 else "CLEAN", "stats": stats}
        else:
            return {"hash": h, "error": f"VT {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def virustotal_check_url_safe(url: str):
    if not VIRUSTOTAL_API_KEY:
        return {"url": url, "error": "VIRUSTOTAL_API_KEY not configured"}
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"accept": "application/json", "x-apikey": VIRUSTOTAL_API_KEY}
        r = requests.get(f"{VIRUSTOTAL_BASE_URL}/urls/{url_id}", headers=headers, timeout=15)
        if r.status_code == 200:
            data = r.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {"url": url, "verdict": "MALICIOUS" if stats.get("malicious",0)>0 else "CLEAN", "stats": stats}
        else:
            return {"url": url, "error": f"VT {r.status_code}"}
    except Exception as e:
        return {"url": url, "error": str(e)}

def abuseipdb_check_ip(ip: str):
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

def check_alert_iocs(alert_json: str, cache: dict):
    alert_data = json.loads(alert_json) if isinstance(alert_json, str) else alert_json
    alert_str = json.dumps(alert_data)
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = set(re.findall(ip_pattern, alert_str))
    public_ips = []
    for ip in ips:
        if ip.startswith(("10.","192.168.","172.","127.","0.","169.254")) or ip == "255.255.255.255":
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

# ========== Playbook classification helpers ==========
def classify_phishing(alert):
    desc = (alert.get("rule", {}) .get("description") or "").lower()
    url = None
    if alert.get("data"):
        url = alert["data"].get("url") or alert["data"].get("uri")
    verdict = "FP"
    reason = "No malicious URL found"
    if url:
        vt = virustotal_check_url_safe(url)
        if vt.get("verdict") == "MALICIOUS":
            verdict = "TP"
            reason = f"VirusTotal flagged URL {url}"
    elif "phish" in desc or "email" in desc:
        verdict = "TP"
        reason = "Rule contains phishing/email keywords"
    return {"category": "phishing", "classification": verdict, "reason": reason}

def classify_malware(alert):
    desc = (alert.get("rule", {}) .get("description") or "").lower()
    file_hash = None
    if alert.get("data"):
        file_hash = alert["data"].get("sha256") or alert["data"].get("md5") or alert["data"].get("sha1")
    verdict = "FP"
    reason = "No malicious file found"
    if file_hash:
        vt = virustotal_check_file_hash(file_hash)
        if vt.get("verdict") == "MALICIOUS":
            verdict = "TP"
            reason = f"VirusTotal flagged hash {file_hash}"
    elif any(k in desc for k in ("malware","trojan","ransom","virus")):
        verdict = "TP"
        reason = "Rule description indicates malware"
    return {"category": "malware", "classification": verdict, "reason": reason}

def classify_ip_connection(alert):
    src_ip = alert.get("srcip") or alert.get("src_ip") or (alert.get("data") or {}).get("srcip")
    verdict = "FP"
    reason = "No malicious IP reported"
    if src_ip:
        verdict = "TP"
        reason = f"Connection to {src_ip}"
    return {"category": "ip_connection", "classification": verdict, "reason": reason}

def classify_web_attack(alert):
    desc = (alert.get("rule", {}) .get("description") or "").lower()
    verdict = "FP"
    reason = "No web exploit indicators"
    keywords = ["xss","sql injection","rce","directory traversal","webshell","lfi","sqli"]
    found = [k for k in keywords if k in desc]
    if found:
        verdict = "TP"
        reason = f"Web attack keywords found: {', '.join(found)}"
    return {"category": "web_attack", "classification": verdict, "reason": reason}

def classify_bruteforce(alert):
    desc = (alert.get("rule", {}) .get("description") or "").lower()
    verdict = "FP"
    reason = "No brute-force pattern"
    if "brute" in desc or "failed password" in desc or "authentication failure" in desc or "login failed" in desc:
        verdict = "TP"
        reason = "Detected repeated auth failures / brute-force pattern"
    return {"category": "bruteforce", "classification": verdict, "reason": reason}

def classify_login_anomaly(alert):
    desc = (alert.get("rule", {}) .get("description") or "").lower()
    verdict = "FP"
    reason = "Normal login"
    if "login" in desc and ("unusual" in desc or "from unknown" in desc or "geolocation" in desc):
        verdict = "TP"
        reason = "Login from abnormal location/time"
    return {"category": "login_anomaly", "classification": verdict, "reason": reason}

# ========== Claude integration (Anthropic) ==========
def claude_classify_alert(alert):
    """Call Claude to analyze alert and return structured JSON. Strict JSON requested."""
    if Anthropic is None or not CLAUDE_API_KEY:
        return {"classification": "FP", "short_reason": "Claude not configured"}

    client = Anthropic(api_key=CLAUDE_API_KEY)
    alert_text = json.dumps(alert, indent=2, ensure_ascii=False)

    prompt = f"""
You are an experienced SOC Level-2 analyst. Analyze the following Wazuh alert JSON and respond STRICTLY in JSON with these keys:
- classification: "TP" or "FP"
- category: phishing, malware, web_attack, ip_connection, bruteforce, login_anomaly, or unknown
- confidence: float between 0.0 and 1.0
- short_reason: one-sentence reason referencing indicators
- recommended_action: one-line SOC action (e.g., "Quarantine host", "Block IP", "Investigate")

Wazuh alert:
{alert_text}
"""

    try:
        resp = client.messages.create(
            model=CLAUDE_MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=400,
            temperature=0.0
        )
        # extract text from the typical response shapes
        text = None
        if hasattr(resp, "content"):
            try:
                text = resp.content[0].text
            except Exception:
                pass
        if not text and isinstance(resp, dict):
            text = resp.get("completion") or resp.get("text") or json.dumps(resp)
        if not text:
            text = str(resp)

        # extract first JSON object
        m = re.search(r'(\{[\s\S]*\})', text)
        if m:
            jtxt = m.group(1)
            try:
                return json.loads(jtxt)
            except Exception:
                return {"classification":"FP","short_reason":"AI returned non-parseable JSON","ai_raw": text}
        else:
            return {"classification":"FP","short_reason":"AI did not return JSON","ai_raw": text}
    except Exception as e:
        return {"classification":"FP","short_reason":f"AI error: {str(e)}"}

# ========== Hybrid merge ==========
def hybrid_merge(playbook_result: dict, ai_result: dict):
    # extract classification from playbook
    playbook_cls = playbook_result.get("classification", "FP")

    # AI disabled → only rely on playbook
    final_tp = (playbook_cls == "TP")

    return {
        "final_classification": "TP" if final_tp else "FP",
        "playbook": playbook_result,
        "ai": ai_result,
        "category": playbook_result.get("category", "general"),
        "reason": playbook_result.get("reason", "No reason provided"),
        "recommended_action": playbook_result.get("reason", "Investigate")
    }
 
# ========== TheHive helpers (v5 API) ==========
def build_thehive_payload(alert, ai_analysis, ioc_summary=None):
    title = (alert.get("rule", {}) .get("description") or f"Wazuh alert {alert.get('rule',{}).get('id','')}")
    level = alert.get("rule", {}).get("level", 0)
    severity = 3 if level >= 10 else 2 if level >= 7 else 1

    description_lines = [
        f"Rule: {alert.get('rule', {}).get('id')} - {alert.get('rule', {}).get('description')}",
        f"Timestamp: {alert.get('@timestamp')}",
        f"Agent: { (alert.get('agent') or {}).get('name') if alert.get('agent') else alert.get('agent') }",
        "\n=== AI Analysis ==="
    ]
    if isinstance(ai_analysis, dict):
        description_lines += [
            f"Classification: {ai_analysis.get('classification')}",
            f"Category: {ai_analysis.get('category')}",
            f"Confidence: {ai_analysis.get('confidence', 'n/a')}",
            f"Reason: {ai_analysis.get('short_reason')}",
            f"Recommended action: {ai_analysis.get('recommended_action')}"
        ]
    else:
        description_lines.append(str(ai_analysis))

    if ioc_summary:
        description_lines.append("\n=== IOC Summary ===")
        for ipobj in ioc_summary.get("ips_checked", []):
            description_lines.append(f"IP {ipobj.get('ip')}: {ipobj.get('verdict')}")

    raw_json_str = json.dumps(alert, indent=2)
    if len(raw_json_str) > 5000:
        raw_json_str = raw_json_str[:5000] + "\n... (truncated)"
    description_lines += ["\n=== Raw Alert (truncated) ===", raw_json_str]

    payload = {
        "title": title[:256],
        "description": "\n".join(description_lines),
        "severity": severity,
        "type": "external",
        "source": "Wazuh-AI",
        "tags": ["Wazuh", "AI", "TP"],
        "raw": alert,
        "sourceRef": f"wazuh-{alert.get('@timestamp')}-{alert.get('rule',{}).get('id')}"
    }
    return payload

def thehive_create_alert(payload: dict, retries: int = 2, backoff: int = 2):
    if not THEHIVE_URL or not THEHIVE_API_KEY:
        raise Exception("THEHIVE_URL or THEHIVE_API_KEY not configured")
    headers = {"Authorization": f"Bearer {THEHIVE_API_KEY}", "Content-Type": "application/json"}
    url = f"{THEHIVE_URL.rstrip('/')}/api/v1/alert"
    attempt = 0
    while attempt <= retries:
        try:
            r = requests.post(url, headers=headers, json=payload, verify=THEHIVE_VERIFY_SSL, timeout=30)
            if r.status_code in (200,201):
                try:
                    return r.json()
                except Exception:
                    return {"status":"ok","raw": r.text}
            else:
                err = f"TheHive API error {r.status_code}: {r.text}"
                if attempt == retries:
                    raise Exception(err)
                attempt += 1
                time.sleep(backoff * attempt)
        except requests.RequestException as e:
            if attempt == retries:
                raise
            attempt += 1
            time.sleep(backoff * attempt)

# ========== Streamer: fetch new alerts and process ==========
def alert_streamer(poll_interval=POLL_INTERVAL_SECONDS, max_batch=MAX_FETCH):
    print(f"[+] Starting alert streamer. Poll {poll_interval}s, batch {max_batch}")
    last_ts = load_last_timestamp()
    print(f"[+] Starting from last timestamp: {last_ts}")
    ioc_cache = load_ioc_cache()

    try:
        while True:
            try:
                alerts = fetch_alerts_since(last_ts, size=max_batch)
            except Exception as e:
                print(f"[!] Error fetching alerts: {e}")
                time.sleep(poll_interval)
                continue

            if not alerts:
                time.sleep(poll_interval)
                continue

            for alert in alerts:
                ts = alert.get("@timestamp") or datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")

                # 1) playbook classification
                desc = (alert.get("rule", {}) .get("description") or "").lower()
                playbook_result = {"category":"general","classification":"FP","reason":"Unclassified"}
                if "phish" in desc or "email" in desc:
                    playbook_result = classify_phishing(alert)
                elif "malware" in desc or "trojan" in desc or "ransom" in desc:
                    playbook_result = classify_malware(alert)
                elif "ip" in desc or "domain" in desc:
                    playbook_result = classify_ip_connection(alert)
                elif "web" in desc or "sql" in desc or "xss" in desc:
                    playbook_result = classify_web_attack(alert)
                elif "brute" in desc or "password" in desc:
                    playbook_result = classify_bruteforce(alert)
                elif "login" in desc or "user" in desc:
                    playbook_result = classify_login_anomaly(alert)

                # 2) call Claude only if suspicious or high-level
                ai_result = {"classification":"FP","short_reason":"Skipped AI"}
                level = alert.get("rule", {}).get("level", 0)
                call_ai = False
                if playbook_result.get("classification") == "TP" or level >= 8:
                    call_ai = True #Modified
                if call_ai:
                    try:
                        ai_result = claude_classify_alert(alert)
                    except Exception as e:
                        ai_result = {"classification":"FP","short_reason": f"AI error: {str(e)}"}

                # 3) hybrid decision
                final = hybrid_merge(playbook_result, ai_result) #Modified

                # 4) if final TP -> check IOCs (cached) and send to TheHive
                if final["final_classification"] == "TP":
                    try:
                        ioc_summary = check_alert_iocs(json.dumps(alert), ioc_cache)
                        payload = build_thehive_payload(alert, ai_result, ioc_summary=ioc_summary)
                        thehive_create_alert(payload)
                        print(f"[+] Sent TP alert to TheHive: {alert.get('rule',{}).get('id')}")
                    except Exception as e:
                        print(f"[!] Error sending to TheHive: {e}")

                # update last_ts for no duplicates
                last_ts = ts
                save_last_timestamp(last_ts)
                # persist IOC cache occasionally
                save_ioc_cache(ioc_cache)

            time.sleep(poll_interval)
    except KeyboardInterrupt:
        print("[*] Stopped by user. Saving cache.")
        save_ioc_cache(ioc_cache)

# ========== Main ==========
if __name__ == "__main__":
    print("Starting Wazuh -> Hybrid -> TheHive pipeline")
    alert_streamer()
