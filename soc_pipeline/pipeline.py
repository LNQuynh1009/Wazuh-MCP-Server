import json
import time
from datetime import datetime

from . import config
from .state import load_last_timestamp, save_last_timestamp, load_ioc_cache, save_ioc_cache
from .opensearch import fetch_alerts_since

from .mcp_server import (
    check_alert_iocs,
    classify_phishing,
    classify_malware,
    classify_ip_connection,
    classify_web_attack,
    classify_bruteforce,
    classify_login_anomaly,
)
from .ai import claude_classify_alert
from .thehive import build_thehive_payload, thehive_create_alert


def hybrid_merge(playbook_result: dict, ai_result: dict):
    playbook_cls = playbook_result.get("classification", "FP")
    final_tp = playbook_cls == "TP"
    return {
        "final_classification": "TP" if final_tp else "FP",
        "playbook": playbook_result,
        "ai": ai_result,
        "category": playbook_result.get("category", "general"),
        "reason": playbook_result.get("reason", "No reason provided"),
        "recommended_action": playbook_result.get("reason", "Investigate"),
    }


def alert_streamer(poll_interval=config.POLL_INTERVAL_SECONDS, max_batch=config.MAX_FETCH):
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
                desc = (alert.get("rule", {}).get("description") or "").lower()
                playbook_result = {"category": "general", "classification": "FP", "reason": "Unclassified"}
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
                ai_result = {"classification": "FP", "short_reason": "Skipped AI"}
                level = alert.get("rule", {}).get("level", 0)
                call_ai = False
                if playbook_result.get("classification") == "TP" or level >= 8:
                    call_ai = True
                if call_ai:
                    try:
                        ai_result = claude_classify_alert(alert)
                    except Exception as e:
                        ai_result = {"classification": "FP", "short_reason": f"AI error: {str(e)}"}

                # 3) hybrid decision
                final = hybrid_merge(playbook_result, ai_result)

                # 4) if final TP -> check IOCs (cached) and send to TheHive
                if final["final_classification"] == "TP":
                    try:
                        ioc_summary = check_alert_iocs(json.dumps(alert), ioc_cache)
                        payload = build_thehive_payload(alert, ai_result, ioc_summary=ioc_summary)
                        thehive_create_alert(payload)
                        print(f"[+] Sent TP alert to TheHive: {alert.get('rule', {}).get('id')}")
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
