# Wazuh-MCP-Server
The server.py is to run a mcp server to connect to wazuh.
The features are still being developed.
To use it please config your claude_desktop_config.json.
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
<pre>
