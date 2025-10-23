# Wazuh-MCP-Server
The server.py is to run a mcp server to connect to wazuh.
The features are still being developed.
To use it please config your claude_desktop_config.json.

Available tools in this MCP Server:
OpenSearch/Wazuh Security Tools and Threat Intelligence Tools
- ping : Test connection to Wazuh API
- list_agents : List registered Wazuh agents (default: 5)
- search_alerts : Run search queries against OpenSearch Wazuh alert indices
- check_alert_iocs : Extract and check all IOCs (IPs, domains, hashes) from Wazuh alert data
- virustotal_check_ip : Check IP address reputation on VirusTotal
- virustotal_check_domain : Check domain reputation on VirusTotal
- virustotal_check_file_hash : Check file hash (MD5/SHA1/SHA256) on VirusTotal
- virustotal_check_url : Check URL reputation on VirusTotal
- abuseipdb_check_ip : Check IP reputation on AbuseIPDB
<pre>
{
  "mcpServers": {
    "opensearch-mcp-server": {
      "command": "/path/to/your/python3",
      "args": ["/path/to/your/server.py"],
      "env": {
        "WAZUH_HOST": "https://<your-wazuh-host>",
        "WAZUH_PORT": "your-wazuh-port",
        "WAZUH_USER": "your-wazuh-username",
        "WAZUH_PASS": "your-wazuh-password",
        "WAZUH_ALLOW_SELF_SIGNED": "true",

        "OPENSEARCH_HOST": "https://<your-opensearch-host>",
        "OPENSEARCH_PORT": "your-opensearch-port",
        "OPENSEARCH_USER": "your-opensearch-username",
        "OPENSEARCH_PASS": "your-opensearch-password",
        "OPENSEARCH_SSL_VERIFY": "false"
      }
    }
  }
}
</pre>


# Members
Le Nhu Quynh: Leader
Tran Thi Thu Phuong: Secretary
Tran Minh Tu: Member
