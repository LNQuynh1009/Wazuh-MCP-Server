#!/usr/bin/env python3

import requests
from requests.auth import HTTPBasicAuth
from config import (
    OPENSEARCH_HOST,
    OPENSEARCH_PORT,
    OPENSEARCH_USER,
    OPENSEARCH_PASS,
    OPENSEARCH_VERIFY
)


def fetch_alerts_since(ts: str, size: int = 500):
    """Fetch alerts with @timestamp > ts in ascending order."""
    base = OPENSEARCH_HOST.rstrip("/")
    url = f"{base}:{OPENSEARCH_PORT}/wazuh-alerts-*/_search"
    query = {
        "size": size,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gt": ts}}},
                    {
                        "terms": {
                            "agent.name": [
                                "DESKTOP-JP58I0C",
                                "Ubuntu-WebServer"
                            ]
                        }
                    }
                ]
            }
        },
        "sort": [{"@timestamp": {"order": "asc"}}]
    }
    resp = requests.get(
        url,
        auth=HTTPBasicAuth(OPENSEARCH_USER, OPENSEARCH_PASS),
        json=query,
        verify=OPENSEARCH_VERIFY,
        timeout=30
    )
    if resp.status_code != 200:
        raise Exception(f"OpenSearch query failed: {resp.status_code} {resp.text}")
    hits = resp.json().get("hits", {}).get("hits", [])
    return [h["_source"] for h in hits]
