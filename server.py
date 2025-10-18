import os
import requests
from fastmcp import FastMCP
from requests.auth import HTTPBasicAuth

# === Load environment variables ===
WAZUH_HOST = os.getenv("WAZUH_HOST", "https://localhost")
WAZUH_PORT = os.getenv("WAZUH_PORT", "55000")
WAZUH_USER = os.getenv("WAZUH_USER", "wazuh-wui")
WAZUH_PASS = os.getenv("WAZUH_PASS", "wazuh-wui")
ALLOW_SELF_SIGNED = os.getenv("WAZUH_ALLOW_SELF_SIGNED", "true").lower() == "true"

VERIFY_SSL = not ALLOW_SELF_SIGNED

BASE_URL = f"{WAZUH_HOST}:{WAZUH_PORT}"
mcp = FastMCP("opensearch-mcp-server")

# === Helper: Get JWT token ===
def get_wazuh_token():
    url = f"{BASE_URL}/security/user/authenticate"
    resp = requests.get(url, auth=(WAZUH_USER, WAZUH_PASS), verify=VERIFY_SSL)
    if resp.status_code != 200:
        raise Exception(f"Auth failed: {resp.text}")
    return resp.json()["data"]["token"]

# === Tool: Ping ===
@mcp.tool()
def ping():
    """Test connection to Wazuh API."""
    try:
        token = get_wazuh_token()
        return {"status": "ok", "token_length": len(token)}
    except Exception as e:
        return {"status": "error", "detail": str(e)}

# === Tool: List agents ===
@mcp.tool()
def list_agents(limit: int = 5):
    """List registered Wazuh agents (default: 5)."""
    try:
        token = get_wazuh_token()
        headers = {"Authorization": f"Bearer {token}"}
        url = f"{BASE_URL}/agents?sort=-ip,name&pretty=true"
        resp = requests.get(url, headers=headers, verify=VERIFY_SSL)
        data = resp.json()
        agents = data.get("data", {}).get("affected_items", [])
        return agents[:limit] if agents else {"message": "No agents found"}
    except Exception as e:
        return {"error": str(e)}
@mcp.tool()
def search_alerts(query: str, size: int = 10):
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
    return hits

if __name__ == "__main__":
    print(f"Starting Wazuh MCP server on {BASE_URL}...")
    mcp.run()
