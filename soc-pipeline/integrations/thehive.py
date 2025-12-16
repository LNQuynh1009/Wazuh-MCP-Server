#!/usr/bin/env python3

import time
import json
import requests
from config import THEHIVE_URL, THEHIVE_API_KEY, THEHIVE_VERIFY_SSL


def build_thehive_payload(alert, ai_analysis, ioc_summary=None):
    """Build a TheHive alert payload from a Wazuh alert and AI analysis."""
    title = (alert.get("rule", {}).get("description") or f"Wazuh alert {alert.get('rule',{}).get('id','')}")
    level = alert.get("rule", {}).get("level", 0)
    severity = 3 if level >= 10 else 2 if level >= 7 else 1

    description_lines = [
        f"Rule: {alert.get('rule', {}).get('id')} - {alert.get('rule', {}).get('description')}",
        f"Timestamp: {alert.get('@timestamp')}",
        f"Agent: {(alert.get('agent') or {}).get('name') if alert.get('agent') else alert.get('agent')}",
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
        "tags": ["Wazuh", "AI", "Pipeline", "SmartSoc"],
        "raw": alert,
        "sourceRef": f"wazuh-{alert.get('@timestamp')}-{alert.get('rule',{}).get('id')}"
    }
    return payload


def thehive_create_alert(payload: dict, retries: int = 2, backoff: int = 2):
    """Create an alert in TheHive with retry logic."""
    if not THEHIVE_URL or not THEHIVE_API_KEY:
        raise Exception("THEHIVE_URL or THEHIVE_API_KEY not configured")
    headers = {"Authorization": f"Bearer {THEHIVE_API_KEY}", "Content-Type": "application/json"}
    url = f"{THEHIVE_URL.rstrip('/')}/api/v1/alert"
    attempt = 0
    while attempt <= retries:
        try:
            r = requests.post(url, headers=headers, json=payload, verify=THEHIVE_VERIFY_SSL, timeout=30)
            if r.status_code in (200, 201):
                try:
                    return r.json()
                except Exception:
                    return {"status": "ok", "raw": r.text}
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
