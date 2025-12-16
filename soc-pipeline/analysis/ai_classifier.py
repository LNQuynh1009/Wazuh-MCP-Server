#!/usr/bin/env python3

import json
import re
from config import CLAUDE_API_KEY, CLAUDE_MODEL

# Optional: Anthropic client
try:
    from anthropic import Anthropic
except Exception:
    Anthropic = None


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
                return {"classification": "FP", "short_reason": "AI returned non-parseable JSON", "ai_raw": text}
        else:
            return {"classification": "FP", "short_reason": "AI did not return JSON", "ai_raw": text}
    except Exception as e:
        return {"classification": "FP", "short_reason": f"AI error: {str(e)}"}
