# Wazuh-MCP-Server
The server.py is to run a mcp server to connect to wazuh.
The features are still being developed.
To use it please config your claude_desktop_config.json.

*!!! Important not: if you want to use soc-pipeline.py make sure you have wazuh and the hive (5.2) installed. And please configed the .env file in the same folder as the soc-pipeline.py.

Available tools in this MCP Server:


Wazuh & OpenSearch Tools
- opensearch-mcp-server:ping. Test connection to the Wazuh API
- opensearch-mcp-server:list_agents. List registered Wazuh agents (default: 5, customizable limit)
- opensearch-mcp-server:search_alerts. Run search queries directly against OpenSearch Wazuh alert indices
- opensearch-mcp-server:classify_and_export_alerts. Fetch last 24h Wazuh alerts, classify as True Positive/False Positive, and export TPs to Excel


Threat Intelligence Tools
- virustotal_check_ip - Check IP address reputation
- virustotal_check_domain - Check domain reputation
- virustotal_check_file_hash - Check file hashes (MD5/SHA1/SHA256)
- virustotal_check_url - Check URL reputation
- abuseipdb_check_ip - Check IP reputation with abuse confidence scores
- Automated IOC Analysis: check_alert_iocs - Extract and check all IOCs (IPs, domains, hashes) from Wazuh alert data automatically
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
- Le Nhu Quynh: Leader

- Tran Thi Thu Phuong: Secretary

- Tran Minh Tu: Member
......
  
