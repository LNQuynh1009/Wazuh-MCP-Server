#!/usr/bin/env python3

import time
import json
import asyncio
import aiohttp
from datetime import datetime

from config import POLL_INTERVAL_SECONDS, MAX_FETCH
from utils.persistence import load_last_timestamp, save_last_timestamp, load_ioc_cache, save_ioc_cache
from integrations.opensearch import fetch_alerts_since
from integrations.thehive import build_thehive_payload
from integrations.async_thehive import async_thehive_create_alert
from analysis.ioc_checker import check_alert_iocs
from analysis.async_ioc_checker import async_check_alert_iocs
from analysis.playbooks import (
    classify_phishing,
    classify_malware,
    classify_ip_connection,
    classify_web_attack,
    classify_bruteforce,
    classify_login_anomaly
)
from analysis.async_ai_classifier import async_claude_classify_alert
from analysis.hybrid import hybrid_merge


async def async_process_single_alert(alert, ioc_cache, session: aiohttp.ClientSession):
    """Process a single alert with concurrent AI + IOC checking."""
    ts = alert.get("@timestamp") or datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    
    # 1) Playbook classification (synchronous, fast)
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
    
    # 2) Determine if we need AI analysis
    ai_result = {"classification": "FP", "short_reason": "Skipped AI"}
    level = alert.get("rule", {}).get("level", 0)
    call_ai = False
    if playbook_result.get("classification") == "TP" or level >= 3:
        call_ai = True
    
    # 3) Run AI classifier and IOC checker concurrently if needed
    ioc_summary = {"ips_checked": []}
    
    if call_ai:
        try:
            # Run AI and IOC checking concurrently
            ai_result, ioc_summary = await asyncio.gather(
                async_claude_classify_alert(alert),
                async_check_alert_iocs(json.dumps(alert), ioc_cache, session),
                return_exceptions=True
            )
            
            # Handle exceptions
            if isinstance(ai_result, Exception):
                ai_result = {"classification": "FP", "short_reason": f"AI error: {str(ai_result)}"}
            if isinstance(ioc_summary, Exception):
                ioc_summary = {"ips_checked": [], "error": str(ioc_summary)}
        except Exception as e:
            ai_result = {"classification": "FP", "short_reason": f"AI error: {str(e)}"}
            ioc_summary = {"ips_checked": []}
    
    # 4) Hybrid decision
    final = hybrid_merge(playbook_result, ai_result)
    
    # 5) If final TP -> send to TheHive (async)
    if final["final_classification"] == "TP":
        try:
            payload = build_thehive_payload(alert, ai_result, ioc_summary=ioc_summary)
            result = await async_thehive_create_alert(payload, session)
            if result.get("success"):
                print(f"[+] Sent TP alert to TheHive: {alert.get('rule',{}).get('id')}")
            else:
                print(f"[!] Error sending to TheHive: {result.get('error')}")
        except Exception as e:
            print(f"[!] Error sending to TheHive: {e}")
    
    return ts


async def async_process_alert_batch(alerts, ioc_cache, session: aiohttp.ClientSession, batch_size=10):
    """Process multiple alerts concurrently in batches."""
    last_ts = None
    
    # Process alerts in batches to avoid overwhelming the system
    for i in range(0, len(alerts), batch_size):
        batch = alerts[i:i + batch_size]
        
        # Process batch concurrently
        tasks = [async_process_single_alert(alert, ioc_cache, session) for alert in batch]
        timestamps = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Get the latest timestamp from this batch
        for ts in timestamps:
            if isinstance(ts, str) and ts:
                last_ts = ts
        
        print(f"[*] Processed batch {i//batch_size + 1}: {len(batch)} alerts")
    
    return last_ts


async def async_alert_streamer(poll_interval=POLL_INTERVAL_SECONDS, max_batch=MAX_FETCH, concurrent_alerts=10):
    """Main async alert processing pipeline with batch processing."""
    print(f"[+] Starting ASYNC alert streamer. Poll {poll_interval}s, batch {max_batch}, concurrent {concurrent_alerts}")
    last_ts = load_last_timestamp()
    print(f"[+] Starting from last timestamp: {last_ts}")
    ioc_cache = load_ioc_cache()
    
    # Create a single aiohttp session for connection pooling
    async with aiohttp.ClientSession() as session:
        try:
            while True:
                try:
                    # Fetch alerts synchronously (OpenSearch client is sync)
                    alerts = fetch_alerts_since(last_ts, size=max_batch)
                except Exception as e:
                    print(f"[!] Error fetching alerts: {e}")
                    time.sleep(poll_interval)
                    continue
                
                if not alerts:
                    time.sleep(poll_interval)
                    continue
                
                print(f"[*] Fetched {len(alerts)} alerts, processing with concurrency={concurrent_alerts}")
                
                # Process alerts asynchronously in batches
                try:
                    new_last_ts = await async_process_alert_batch(alerts, ioc_cache, session, batch_size=concurrent_alerts)
                    
                    if new_last_ts:
                        last_ts = new_last_ts
                        save_last_timestamp(last_ts)
                    
                    # Save IOC cache after each batch
                    save_ioc_cache(ioc_cache)
                except Exception as e:
                    print(f"[!] Error processing batch: {e}")
                
                time.sleep(poll_interval)
        except KeyboardInterrupt:
            print("[*] Stopped by user. Saving cache.")
            save_ioc_cache(ioc_cache)
