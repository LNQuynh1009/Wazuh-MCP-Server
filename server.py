import os
from dotenv import load_dotenv
from soc_pipeline.mcp_server import mcp, BASE_URL, VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY

# === Load environment variables ===
load_dotenv()

if __name__ == "__main__":
    print(f"Starting Wazuh MCP server on {BASE_URL}...")
    print(f"VirusTotal API: {'Configured' if VIRUSTOTAL_API_KEY else 'Not configured'}")
    print(f"AbuseIPDB API: {'Configured' if ABUSEIPDB_API_KEY else 'Not configured'}")
    mcp.run()
