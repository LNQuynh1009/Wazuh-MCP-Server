#!/usr/bin/env python3

import aiohttp
from config import THEHIVE_URL, THEHIVE_API_KEY


async def async_thehive_create_alert(payload: dict, session: aiohttp.ClientSession):
    """Create an alert in TheHive (async)."""
    if not THEHIVE_URL or not THEHIVE_API_KEY:
        return {"error": "TheHive not configured"}
    
    headers = {
        "Authorization": f"Bearer {THEHIVE_API_KEY}",
        "Content-Type": "application/json"
    }
    
    try:
        async with session.post(
            f"{THEHIVE_URL}/api/v1/alert",
            headers=headers,
            json=payload,
            timeout=aiohttp.ClientTimeout(total=30)
        ) as r:
            if r.status in (200, 201):
                data = await r.json()
                return {"success": True, "alert_id": data.get("_id")}
            else:
                text = await r.text()
                return {"error": f"TheHive {r.status}: {text}"}
    except Exception as e:
        return {"error": str(e)}
