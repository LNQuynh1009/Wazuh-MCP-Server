# Wazuh-MCP-Server

## Modular Structure (refactor)

The pipeline has been refactored into a Python package for clarity and reuse:

- `soc-pipeline.py`: Thin entrypoint that starts the pipeline
- `soc_pipeline/` package:
  - `config.py`: environment configuration and constants
  - `state.py`: persistent timestamp and IOC cache helpers
  - `opensearch.py`: OpenSearch alert queries
  - `intel.py`: VirusTotal/AbuseIPDB lookups and IOC extraction
  - `classifiers.py`: rule-based/playbook classifiers
  - `ai.py`: Claude (Anthropic) classification
  - `thehive.py`: TheHive payload + API client
  - `pipeline.py`: orchestrator loop

### Setup

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Run

```powershell
python soc-pipeline.py
```

Ensure `.env` is configured as shown below. The pipeline resumes from `last_ts.txt` and updates `ioc_cache.json` automatically.
The server.py is to run a mcp server to connect to wazuh.
The features are still being developed.
To use it please config your claude_desktop_config.json.

*!!! Important note: if you want to use soc-pipeline.py make sure you have wazuh and the hive (5.2) installed. And please configed the .env file in the same folder as the soc-pipeline.py. The AI feature (Claude) is coming soon.

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


Here is the .env example. Please use this with the soc-pipeline.py
<pre>
# Wazuh
WAZUH_HOST=https://wazuh-ip
WAZUH_PORT=55000
WAZUH_USER=yourpasswd
WAZUH_PASS=yourpasswd

# OpenSearch
OPENSEARCH_HOST=https://wazuh-ip
OPENSEARCH_PORT=9200
OPENSEARCH_USER=youropensearchpasswd
OPENSEARCH_PASS=youropensearchpasswd
OPENSEARCH_SSL_VERIFY=false

# Claude API
#ANTHROPIC_API_KEY=your_key_here #Uncomment this if you use AI features

# VirusTotal
VIRUSTOTAL_API_KEY=YourVTKey

# AbuseIPDB
ABUSEIPDB_API_KEY=YourAbuseIPKey

# TheHive
THEHIVE_URL=http://thehive-ip:9000
THEHIVE_API_KEY=thehiveAPI
THEHIVE_SSL_VERIFY=false
</pre>

# Members
- Le Nhu Quynh: Leader

- Tran Thi Thu Phuong: Secretary

- Tran Minh Tu: Member
......
  
