#!/usr/bin/env python3

import os
from dotenv import load_dotenv

# Load .env from current working directory
load_dotenv()

# ========== Wazuh Configuration ==========
WAZUH_HOST = os.getenv("WAZUH_HOST", "https://localhost")
WAZUH_PORT = os.getenv("WAZUH_PORT", "55000")
WAZUH_USER = os.getenv("WAZUH_USER", "wazuh-wui")
WAZUH_PASS = os.getenv("WAZUH_PASS", "wazuh-wui")
ALLOW_SELF_SIGNED = os.getenv("WAZUH_ALLOW_SELF_SIGNED", "true").lower() == "true"
BASE_URL = f"{WAZUH_HOST}:{WAZUH_PORT}"

# ========== OpenSearch Configuration ==========
OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "http://127.0.0.1")
OPENSEARCH_PORT = os.getenv("OPENSEARCH_PORT", "9200")
OPENSEARCH_USER = os.getenv("OPENSEARCH_USER")
OPENSEARCH_PASS = os.getenv("OPENSEARCH_PASS")
OPENSEARCH_VERIFY = os.getenv("OPENSEARCH_SSL_VERIFY", "false").lower() == "true"

# ========== Threat Intel Configuration ==========
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"

# ========== Claude / Anthropic Configuration ==========
# Support both names: CLAUDE_API_KEY or ANTHROPIC_API_KEY
CLAUDE_API_KEY = os.getenv("CLAUDE_API_KEY") or os.getenv("ANTHROPIC_API_KEY")
CLAUDE_MODEL = os.getenv("CLAUDE_MODEL", "claude-sonnet-4-5")

# ========== TheHive Configuration ==========
THEHIVE_URL = os.getenv("THEHIVE_URL")
THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY")
THEHIVE_VERIFY_SSL = os.getenv("THEHIVE_VERIFY_SSL", "false").lower() == "true"

# ========== Pipeline Tuning ==========
POLL_INTERVAL_SECONDS = int(os.getenv("POLL_INTERVAL_SECONDS", "30"))
MAX_FETCH = int(os.getenv("MAX_FETCH", "500"))

# ========== Persistent Files ==========
LAST_TS_FILE = os.getenv("LAST_TS_FILE", "last_ts.txt")
IOC_CACHE_FILE = os.getenv("IOC_CACHE_FILE", "ioc_cache.json")
