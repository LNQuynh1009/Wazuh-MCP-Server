import requests
from requests.auth import HTTPBasicAuth
from . import config


def fetch_alerts_since(ts: str, size: int = 500):
    """Fetch alerts with @timestamp > ts in ascending order from OpenSearch."""
    base = config.OPENSEARCH_HOST.rstrip("/")
    url = f"{base}:{config.OPENSEARCH_PORT}/wazuh-alerts-*/_search"
    query = {
        "size": size,
        "query": {"range": {"@timestamp": {"gt": ts}}},
        "sort": [{"@timestamp": {"order": "asc"}}],
    }
    resp = requests.get(
        url,
        auth=HTTPBasicAuth(config.OPENSEARCH_USER, config.OPENSEARCH_PASS),
        json=query,
        verify=config.OPENSEARCH_VERIFY,
        timeout=30,
    )
    if resp.status_code != 200:
        raise Exception(f"OpenSearch query failed: {resp.status_code} {resp.text}")
    hits = resp.json().get("hits", {}).get("hits", [])
    return [h.get("_source", {}) for h in hits]
