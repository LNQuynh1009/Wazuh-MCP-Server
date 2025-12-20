#!/usr/bin/env python3


def classify_phishing(alert):
    """Classify phishing alerts based on keywords (API calls moved to IOC checker)."""
    desc = (alert.get("rule", {}).get("description") or "").lower()
    verdict = "FP"
    reason = "No phishing indicators found"
    
    # Keyword-based classification only
    if "phish" in desc or "email" in desc or "suspicious" in desc:
        verdict = "TP"
        reason = "Rule contains phishing/email keywords"
    
    return {"category": "phishing", "classification": verdict, "reason": reason}


def classify_malware(alert):
    """Classify malware alerts based on keywords (API calls moved to IOC checker)."""
    desc = (alert.get("rule", {}).get("description") or "").lower()
    verdict = "FP"
    reason = "No malware indicators found"
    
    # Keyword-based classification only
    if any(k in desc for k in ("malware", "trojan", "ransom", "virus", "backdoor", "rootkit")):
        verdict = "TP"
        reason = "Rule description indicates malware"
    
    return {"category": "malware", "classification": verdict, "reason": reason}


def classify_ip_connection(alert):
    """Classify IP connection alerts."""
    src_ip = alert.get("srcip") or alert.get("src_ip") or (alert.get("data") or {}).get("srcip")
    verdict = "FP"
    reason = "No malicious IP reported"
    if src_ip:
        verdict = "TP"
        reason = f"Connection to {src_ip}"
    return {"category": "ip_connection", "classification": verdict, "reason": reason}


def classify_web_attack(alert):
    """Classify web attack alerts based on keywords."""
    desc = (alert.get("rule", {}).get("description") or "").lower()
    verdict = "FP"
    reason = "No web exploit indicators"
    keywords = ["xss", "sql injection", "rce", "directory traversal", "webshell", "lfi", "sqli"]
    found = [k for k in keywords if k in desc]
    if found:
        verdict = "TP"
        reason = f"Web attack keywords found: {', '.join(found)}"
    return {"category": "web_attack", "classification": verdict, "reason": reason}


def classify_bruteforce(alert):
    """Classify brute-force alerts based on authentication failure indicators."""
    desc = (alert.get("rule", {}).get("description") or "").lower()
    verdict = "FP"
    reason = "No brute-force pattern"
    if "brute" in desc or "failed password" in desc or "authentication failure" in desc or "login failed" in desc:
        verdict = "TP"
        reason = "Detected repeated auth failures / brute-force pattern"
    return {"category": "bruteforce", "classification": verdict, "reason": reason}


def classify_login_anomaly(alert):
    """Classify login anomaly alerts based on unusual location/time patterns."""
    desc = (alert.get("rule", {}).get("description") or "").lower()
    verdict = "FP"
    reason = "Normal login"
    if "login" in desc and ("unusual" in desc or "from unknown" in desc or "geolocation" in desc):
        verdict = "TP"
        reason = "Login from abnormal location/time"
    return {"category": "login_anomaly", "classification": verdict, "reason": reason}
