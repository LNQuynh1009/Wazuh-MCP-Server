# import os
# import requests
# import json
# import re
# import base64
# from fastmcp import FastMCP
# from requests.auth import HTTPBasicAuth

# from dotenv import load_dotenv
# import os
# import datetime
# from urllib.parse import urlparse

# # === Load environment variables from file env===
# load_dotenv()

# WAZUH_HOST = os.getenv("WAZUH_HOST")
# WAZUH_PORT = os.getenv("WAZUH_PORT")
# WAZUH_USER = os.getenv("WAZUH_USER")
# WAZUH_PASS = os.getenv("WAZUH_PASS")
# ALLOW_SELF_SIGNED = os.getenv("WAZUH_ALLOW_SELF_SIGNED", "true").lower() == "true"
# VERIFY_SSL = not ALLOW_SELF_SIGNED
# BASE_URL = f"{WAZUH_HOST}:{WAZUH_PORT}"

# # === Threat Intelligence APIs ===
# VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
# VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"
# ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
# ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"
# IP2LOCATION_API_KEY = os.getenv("IP2LOCATION_API_KEY")

# mcp = FastMCP("opensearch-mcp-server")

# # === Helper: Get JWT token ===
# def get_wazuh_token():
#     url = f"{BASE_URL}/security/user/authenticate"
#     resp = requests.get(url, auth=(WAZUH_USER, WAZUH_PASS), verify=VERIFY_SSL)
#     if resp.status_code != 200:
#         raise Exception(f"Auth failed: {resp.text}")
#     return resp.json()["data"]["token"]

# # ========== EXISTING WAZUH TOOLS ==========

# @mcp.tool()
# def ping():
#     """Test connection to Wazuh API."""
#     try:
#         token = get_wazuh_token()
#         return {"status": "ok", "token_length": len(token)}
#     except Exception as e:
#         return {"status": "error", "detail": str(e)}

# @mcp.tool()
# def list_agents(limit: int = 5):
#     """List registered Wazuh agents (default: 5)."""
#     try:
#         token = get_wazuh_token()
#         headers = {"Authorization": f"Bearer {token}"}
#         url = f"{BASE_URL}/agents?sort=-ip,name&pretty=true"
#         resp = requests.get(url, headers=headers, verify=VERIFY_SSL)
#         data = resp.json()
#         agents = data.get("data", {}).get("affected_items", [])
#         return agents[:limit] if agents else {"message": "No agents found"}
#     except Exception as e:
#         return {"error": str(e)}

# @mcp.tool()
# def search_alerts(query: str, size: int = 100):
#     """Run a search query directly against the OpenSearch Wazuh alert indices."""
#     host = os.getenv("OPENSEARCH_HOST")
#     port = os.getenv("OPENSEARCH_PORT", "9200")
#     user = os.getenv("OPENSEARCH_USER")
#     password = os.getenv("OPENSEARCH_PASS")
#     verify_ssl = os.getenv("OPENSEARCH_SSL_VERIFY", "true").lower() == "true"
    
#     url = f"{host}:{port}/wazuh-alerts-*/_search"
#     payload = {
#         "size": size,
#         "query": {
#             "query_string": {
#                 "query": query
#             }
#         },
#         "sort": [{"@timestamp": {"order": "desc"}}]
#     }
    
#     response = requests.get(url, auth=HTTPBasicAuth(user, password), json=payload, verify=verify_ssl)
#     if response.status_code != 200:
#         return {"error": response.text}
    
#     data = response.json()
#     hits = [hit["_source"] for hit in data.get("hits", {}).get("hits", [])]
#     return hits

# # ========== NEW: VIRUSTOTAL TOOLS ==========
# def virustotal_check_ip(ip: str):
#     """Check an IP address reputation on VirusTotal.
    
#     Args:
#         ip: IP address to check (e.g., '8.8.8.8')
    
#     Returns:
#         Dict with reputation, malicious detections, country, ASN, etc.
#     """
#     if not VIRUSTOTAL_API_KEY:
#         return {"error": "VIRUSTOTAL_API_KEY not set in environment"}
    
#     try:
#         headers = {
#             "accept": "application/json",
#             "x-apikey": VIRUSTOTAL_API_KEY
#             }
#         response = requests.get(
#             f"{VIRUSTOTAL_BASE_URL}/ip_addresses/{ip}",
#             headers=headers
#         )
        
#         if response.status_code == 200:
#             data = response.json().get("data", {})
#             attributes = data.get("attributes", {})
#             return attributes

#         elif response.status_code == 404:
#             return {"ip": ip, "verdict": "NOT_FOUND", "message": "IP not found in VirusTotal database"}
#         else:
#             return {"error": f"VT API error {response.status_code}: {response.text}"}
#     except Exception as e:
#         return {"error": str(e)}

# def abuseipdb_check_ip(ip: str):
#     """Check IP reputation on AbuseIPDB.
    
#     Args:
#         ip: IP address to check (e.g., '1.2.3.4')
    
#     Returns:
#         Dict with abuse confidence score, reports, country, ISP, etc.
#     """
#     if not ABUSEIPDB_API_KEY:
#         return {"error": "ABUSEIPDB_API_KEY not set in environment"}
    
#     try:
#         headers = {
#             "Key": ABUSEIPDB_API_KEY,
#             "Accept": "application/json"
#         }
#         params = {
#             "ipAddress": ip,
#             "maxAgeInDays": 90,
#             "verbose": ""
#         }
        
#         response = requests.get(
#             f"{ABUSEIPDB_BASE_URL}/check",
#             headers=headers,
#             params=params
#         )
        
#         if response.status_code == 200:
#             data = response.json().get("data", {})
#             with open("abuseipdb_response.json", "w") as f:
#                 json.dump(data, f, indent=4)
#             return data
#         else:
#             return {"error": f"AbuseIPDB API error {response.status_code}: {response.text}"}
#     except Exception as e:
#         return {"error": str(e)}

# def check_ip2location(ip: str):
#     """Check IP geolocation using ip2location 
#     Args:
#         ip: IP address to check (e.g., '
#     """
#     try:
#         print(IP2LOCATION_API_KEY)
#         response = requests.get(f"https://api.ip2location.io/?key={IP2LOCATION_API_KEY}&ip={ip}&format=json")
#         if response.status_code == 200:
#             data = response.json()
#             with open("ip2location_response.json", "w") as f:
#                 json.dump(data, f, indent=4)
#             return data
#         else:
#             return {"error": f"ip2location API error {response.status_code}: {response.text}"}
#     except Exception as e:
#         return {"error": str(e)}

# def virustotal_check_domain(domain: str):
#     """Check a domain reputation on VirusTotal.
    
#     Args:
#         domain: Domain to check (e.g., 'google.com')
    
#     Returns:
#         Dict with reputation, malicious detections, categories, etc.
#     """
#     if not VIRUSTOTAL_API_KEY:
#         return {"error": "VIRUSTOTAL_API_KEY not set in environment"}
    
#     try:
#         headers = {
#             "accept": "application/json",
#             "x-apikey": VIRUSTOTAL_API_KEY}
#         response = requests.get(
#             f"{VIRUSTOTAL_BASE_URL}/domains/{domain}",
#             headers=headers
#         )
        
#         if response.status_code == 200:
#             data = response.json().get("data", {})
#             attributes = data.get("attributes", {})
#             return attributes

#         elif response.status_code == 404:
#             return {"domain": domain, "verdict": "NOT_FOUND", "message": "Domain not found in VirusTotal database"}
#         else:
#             return {"error": f"VT API error {response.status_code}: {response.text}"}
#     except Exception as e:
#         return {"error": str(e)}

# def virustotal_check_file_hash(file_hash: str):
#     """Check a file hash (MD5, SHA1, or SHA256) on VirusTotal.
    
#     Args:
#         file_hash: File hash to check (MD5/SHA1/SHA256)
    
#     Returns:
#         Dict with file info, malicious detections, reputation, etc.
#     """
#     if not VIRUSTOTAL_API_KEY:
#         return {"error": "VIRUSTOTAL_API_KEY not set in environment"}
    
#     try:
#         headers = {"x-apikey": VIRUSTOTAL_API_KEY}
#         response = requests.get(
#             f"{VIRUSTOTAL_BASE_URL}/files/{file_hash}",
#             headers=headers
#         )
        
#         if response.status_code == 200:
#             data = response.json().get("data", {})
#             attributes = data.get("attributes", {})
#             return attributes

#         elif response.status_code == 404:
#             return {"hash": file_hash, "verdict": "NOT_FOUND", "message": "Hash not found in VirusTotal database"}
#         else:
#             return {"error": f"VT API error {response.status_code}: {response.text}"}
#     except Exception as e:
#         return {"error": str(e)}

# def virustotal_check_url(url: str):
#     """Check a URL reputation on VirusTotal.
    
#     Args:
#         url: URL to check (e.g., 'https://example.com')
    
#     Returns:
#         Dict with URL reputation, malicious detections, categories, etc.
#     """
#     if not VIRUSTOTAL_API_KEY:
#         return {"error": "VIRUSTOTAL_API_KEY not set in environment"}
    
#     try:
#         # VirusTotal uses base64 URL-safe encoding for URL identifiers
#         url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
#         headers = {"x-apikey": VIRUSTOTAL_API_KEY}
#         response = requests.get(
#             f"{VIRUSTOTAL_BASE_URL}/urls/{url_id}",
#             headers=headers
#         )
        
#         if response.status_code == 200:
#             data = response.json().get("data", {})
#             attributes = data.get("attributes", {})
            
#             return {
#                 "url": url,
#                 "reputation": attributes.get("reputation"),
#                 "last_analysis_stats": attributes.get("last_analysis_stats"),
#                 "malicious": attributes.get("last_analysis_stats", {}).get("malicious", 0),
#                 "suspicious": attributes.get("last_analysis_stats", {}).get("suspicious", 0),
#                 "harmless": attributes.get("last_analysis_stats", {}).get("harmless", 0),
#                 "undetected": attributes.get("last_analysis_stats", {}).get("undetected", 0),
#                 "categories": attributes.get("categories"),
#                 "last_submission_date": attributes.get("last_submission_date"),
#                 "verdict": "MALICIOUS" if attributes.get("last_analysis_stats", {}).get("malicious", 0) > 0 else "CLEAN"
#             }
#         elif response.status_code == 404:
#             return {"url": url, "verdict": "NOT_FOUND", "message": "URL not found in VirusTotal database"}
#         else:
#             return {"error": f"VT API error {response.status_code}: {response.text}"}
#     except Exception as e:
#         return {"error": str(e)}

# # ========== NEW: BULK IOC CHECKER ==========
# @mcp.tool()
# def check_alert_iocs(alert_json: str):
#     """
#     Extract and check all IOCs (IPs, domains, hashes) from Wazuh alert data
#     using internal playbook functions:
#     - evaluate_domain_playbook(domain)
#     - check_file_playbook(file_hash, path)
#     - evaluate_ip_threat(ip)

#     Args:
#         alert_json: JSON string of alert data from search_alerts

#     Returns:
#         Dict with checked IOCs: IPs, domains, hashes
#     """
#     try:
#         # --- Parse alert JSON ---
#         if isinstance(alert_json, str):
#             alert_data = json.loads(alert_json)
#         else:
#             alert_data = alert_json

#         alert_str = json.dumps(alert_data)

#         results = {
#             "summary": {
#                 "total_ips_found": 0,
#                 "total_domains_found": 0,
#                 "total_hashes_found": 0,
#                 "ips_checked": 0,
#                 "domains_checked": 0,
#                 "hashes_checked": 0
#             },
#             "ips": [],
#             "domains": [],
#             "hashes": []
#         }

#         # =============================
#         # 1. Extract IP ADDRESSES
#         # =============================
#         ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
#         ips = set(re.findall(ip_pattern, alert_str))
#         results["summary"]["total_ips_found"] = len(ips)

#         # Exclude private IP ranges
#         private_ip_patterns = [
#             r'^10\.',
#             r'^172\.(1[6-9]|2[0-9]|3[01])\.',
#             r'^192\.168\.',
#             r'^127\.',
#             r'^169\.254\.',
#             r'^0\.',
#             r'^255\.'
#         ]

#         public_ips = [
#             ip for ip in ips
#             if not any(re.match(p, ip) for p in private_ip_patterns)
#             and ip != "0.0.0.0"
#         ]

#         for ip in public_ips:
#             ip_result = evaluate_ip_threat(ip)

#             results["ips"].append({
#                 "ip": ip,
#                 "result": ip_result
#             })

#             results["summary"]["ips_checked"] += 1

#         # =============================
#         # 2. Extract DOMAIN NAMES
#         # =============================
#         domain_pattern = r"\b([a-zA-Z0-9-]+\.[a-zA-Z]{2,})\b"
#         domains = set(re.findall(domain_pattern, alert_str))
#         results["summary"]["total_domains_found"] = len(domains)

#         for domain in list(domains):
#             dom_result = evaluate_domain_playbook(domain)

#             results["domains"].append({
#                 "domain": domain,
#                 "result": dom_result
#             })

#             results["summary"]["domains_checked"] += 1

#         # =============================
#         # 3. Extract FILE HASHES
#         # =============================
#         md5_pattern = r"\b[a-fA-F0-9]{32}\b"
#         sha1_pattern = r"\b[a-fA-F0-9]{40}\b"
#         sha256_pattern = r"\b[a-fA-F0-9]{64}\b"

#         hashes = set(re.findall(md5_pattern, alert_str)
#                      + re.findall(sha1_pattern, alert_str)
#                      + re.findall(sha256_pattern, alert_str))

#         results["summary"]["total_hashes_found"] = len(hashes)

#         for file_hash in hashes:
#             file_result = check_file_playbook(file_hash, path="")

#             results["hashes"].append({
#                 "hash": file_hash,
#                 "result": file_result
#             })

#             results["summary"]["hashes_checked"] += 1

#         return results

#     except Exception as e:
#         return {"error": str(e)}
    
# #Lấy thông tin về hardware, processes, os, package, network treena agent
# # === Hàm gọi API Wazuh ===
# def wazuh_get(path, params=None):
#     token = get_wazuh_token()
#     headers = {"Authorization": f"Bearer {token}"}
#     url = f"{BASE_URL}{path}"
#     print(f"DEBUG URL: {url}")
#     resp = requests.get(url, headers=headers, params=params, verify=VERIFY_SSL)
#     resp.raise_for_status()
#     return resp.json()

# # === Lấy toàn bộ thông tin hệ thống của agent ===
# @mcp.tool()
# def get_agent_syscollector(agent_id):
#     """
#     Retrieve all system information of an agent through Wazuh's Syscollector API.

#     The collected information includes:

#     - os: Operating system information (Windows, Linux, etc.)
#     - netiface: Network interface information      
#     - netport: Open network ports on the agent
#     - netproto: Network protocols in use
#     - packages: Installed software packages
#     - processes: Running processes
#     - ports: Related/existing ports
#     - hardware: Hardware information of the agent
#     - hotfixes: Security patches installed on the system

#     Parameters:
#     agent_id (str): The ID of the agent to retrieve information from.

#     Returns:
#     dict: A dictionary containing the agent_id and syscollector data of each module.
#     If any module API call fails, the response will include the error and the corresponding HTTP status code.

#     """
#     modules = [
#         "os",          # thông tin hệ điều hành
#         "netiface",    # card mạng
#         "netport",     # cổng đang mở
#         "netproto",    # giao thức mạng
#         "packages",    # gói cài đặt
#         "processes",   # tiến trình đang chạy
#         "ports",
#         "hardware", 
#         "hotfixes"
#     ]

#     result = {"agent_id": agent_id, "syscollector": {}}

#     for module in modules:
#         path = f"/syscollector/{agent_id}/{module}"
#         #path = f"/agents/{agent_id}/syscollector/{module}"
#         try:
#             data = wazuh_get(path)
#             result["syscollector"][module] = data.get("data", {}).get("affected_items", [])
#         except requests.HTTPError as e:
#             result["syscollector"][module] = {"error": str(e), "status": e.response.status_code}
#     return result

# #=========Mapping mitre technique============= 
# import json
# import os
# from urllib.request import urlopen
# from bs4 import BeautifulSoup

# #=========classes=============
# class technique:   #attack-pattern
#     def __init__(self, id, name, description=None, url=None):
#         self.id = id #đây không phải id của technique mà là stix id
#         self.external_id = None  # Txxxx, đây là id của technique
#         self.name = name
#         self.description = description
#         self.url = url
#         self.phase = []  # kill_chain_phases
#         self.detection = []
#         self.platforms = []
#         self.data_sources = []
#         self.mitigations = []  # list of mitigation ids
#         self.groups = []       # list of group ids
#         self.malwares = []     # list of malware ids
#         self.tools = []        # list of tool ids
#         self.campaigns = []  # list of campaign ids

# class group_attacker:  #intrusion-set
#     def __init__(self, id, name, description=None, url=None):
#         self.id = id
#         self.name = name
#         self.description = description
#         self.url = url
#         self.external_id = None #Gxxxx
#         self.techniques = []

# class malware:   #malware
#     def __init__(self, id, name, description=None, url=None):
#         self.id = id
#         self.name = name
#         self.description = description
#         self.url = url
#         self.external_id = None #Sxxxx
#         self.techniques = []

# class tool:   #tool
#     def __init__(self, id, description=None, url=None):
#         self.id = id
#         self.description = description
#         self.url = url
#         self.external_id = None #Sxxxx
#         self.techniques = []

# class campaign:  #campaign
#     def __init__(self, id, name, description=None, url=None):
#         self.id = id
#         self.name = name
#         self.description = description
#         self.url = url
#         self.external_id = None  # Cxxxx
#         self.first_seen = None
#         self.last_seen = None
#         self.techniques = []

# class mitigation:  #course-of-action
#     def __init__(self, id, name, description=None, url=None):
#         self.id = id
#         self.name = name
#         self.description = description
#         self.url = url
#         self.techniques = []  # techniques mitigated by this action


# class mitre_repository:
#     def __init__(self, json_path):
#         self.techniques = {}
#         self.groups = {}        
#         self.malwares = {}
#         self.tools = {}
#         self.mitigations = {}
#         self.external_id_map = {}  # T1078 → stix-id
#         self.relationships = []  # list of relationships
#         self.campaigns = {}

#         self.load(json_path)
#         self.resolve_relationships()

#     def load(self, path):
#         with open(path, "r", encoding="utf-8") as f:
#             data = json.load(f)
#         list_objs = data.get("objects", [])
#         for obj in list_objs:
#             t = obj.get("type")

#             # TECHNIQUE (Txxxx)
#             if t == "attack-pattern":
#                 o = technique(obj["id"], obj["name"], obj.get("description"))

#                 # external_id (Txxxx)
#                 for ref in obj.get("external_references", []):
#                     if ref.get("source_name") == "mitre-attack":
#                         o.external_id = ref.get("external_id")
#                         o.url = ref.get("url")
#                         break
#                 if obj.get("kill_chain_phases"):
#                     for kill in obj.get("kill_chain_phases", []):
#                         phase = kill.get("phase_name")
#                         o.phase.append(phase)

#                 if obj.get("x_mitre_detection"):
#                     detection = obj.get("x_mitre_detection")
#                     o.detection.append(detection)

#                 if obj.get("x_mitre_platforms"):
#                     platforms = obj.get("x_mitre_platforms")
#                     o.platforms.extend(platforms)
                
#                 if obj.get("x_mitre_data_sources"):
#                     data_sources = obj.get("x_mitre_data_sources")
#                     o.data_sources.extend(data_sources)
#                 self.techniques[obj["id"]] = o
#                 self.external_id_map[o.external_id] = obj["id"]

#             # GROUP
#             elif t == "intrusion-set":
#                 o = group_attacker(obj["id"], obj["name"], obj.get("description"))
#                 # external_id (Txxxx)
#                 for ref in obj.get("external_references", []):
#                     if ref.get("source_name") == "mitre-attack":
#                         o.external_id = ref.get("external_id")
#                         o.url = ref.get("url")
#                         break
#                 self.groups[obj["id"]] = o

#             # TOOL
#             elif t == "tool":
#                 o = tool(obj["id"], obj.get("description"))
#                 for ref in obj.get("external_references", []):
#                     if ref.get("source_name") == "mitre-attack":
#                         o.external_id = ref.get("external_id")
#                         o.url = ref.get("url")
#                         break
#                 self.tools[obj["id"]] = o

#             # MALWARE
#             elif t == "malware":
#                 o = malware(obj["id"], obj["name"], obj.get("description"))
#                 for ref in obj.get("external_references", []):
#                     if ref.get("source_name") == "mitre-attack":
#                         o.external_id = ref.get("external_id")
#                         o.url = ref.get("url")
#                         break
#                 self.malwares[obj["id"]] = o

#             # MITIGATION
#             elif t == "course-of-action":
#                 o = mitigation(obj["id"], obj["name"], obj.get("description"))
#                 for ref in obj.get("external_references", []):
#                     if ref.get("source_name") == "mitre-attack":
#                         o.external_id = ref.get("external_id")
#                         o.url = ref.get("url")
#                         break
#                 self.mitigations[obj["id"]] = o
            
#             elif t == "campaign":
#                 o = campaign(obj["id"], obj["name"], obj.get("description"))
#                 for ref in obj.get("external_references", []):
#                     if ref.get("source_name") == "mitre-attack":
#                         o.external_id = ref.get("external_id")
#                         o.url = ref.get("url")
#                         break
#                 o.first_seen = obj.get("first_seen")
#                 o.last_seen = obj.get("last_seen")
#                 self.campaigns[obj["id"]] = o
            
#             elif t == "relationship":
#                 self.relationships.append(obj)
#         self.resolve_relationships()

#     def resolve_relationships(self):
#         for rel in self.relationships:
#             src = rel.get("source_ref")
#             tgt = rel.get("target_ref")
#             t = rel.get("relationship_type")

#             # technique mitigated by course-of-action
#             if t == "mitigates":
#                 if src in self.mitigations and tgt in self.techniques:
#                     self.mitigations[src].techniques.append(self.techniques[tgt])
#                     self.techniques[tgt].mitigations.append(self.mitigations[src])
#             # technique used by group
#             elif t == "uses":
#                 if src in self.groups and tgt in self.techniques:
#                     self.groups[src].techniques.append(self.techniques[tgt])
#                     self.techniques[tgt].groups.append(self.groups[src])
#                 if src in self.malwares and tgt in self.techniques:
#                     self.malwares[src].techniques.append(self.techniques[tgt])
#                     self.techniques[tgt].malwares.append(self.malwares[src])
#                 if src in self.tools and tgt in self.techniques:
#                     self.tools[src].techniques.append(self.techniques[tgt])
#                     self.techniques[tgt].tools.append(self.tools[src])
#                 if src in self.campaigns and tgt in self.techniques:
#                     self.campaigns[src].techniques.append(self.techniques[tgt])
#                     self.techniques[tgt].campaigns.append(self.campaigns[src])

#     def find_technique_by_external_id(self, external_id) -> technique | None:
#         stix_id = self.external_id_map.get(external_id)
#         if stix_id:
#             return self.techniques.get(stix_id)
#         return None
# #=========end classes=============

# #=========functions===============
# def extract_techniques(json_alert):
#     techniques = json_alert.get("_source").get("rule").get("mitre").get("id")
#     return techniques

# def get_full_description_from_url(url: str) -> str:
#     try:
#         html = urlopen(url).read()
#         soup = BeautifulSoup(html, "html.parser")

#         # phần mô tả luôn nằm trong <div class="description-body">
#         desc = soup.find("div", {"class": "description-body"})
#         if desc:
#             return desc.get_text(strip=True)
#         return "No description found!"
#     except Exception as e:
#         return f"Error: {e}"

# # Load MITRE JSON
# from mcp.types import TextContent
# MITRE_PATH = os.getenv("MITRE_ATTACK_PATH", "D:/DoAn/code/Wazuh-MCP-Server/enterprise-attack.json")
# def load_repo():
#     return mitre_repository(MITRE_PATH)

# #=========end functions===============

# # ===================  MCP SERVER  ========================================
# @mcp.tool() #tool này không cần nhưng bỏ thì tiếc :)))
# def extract_techniques(json_alert):
#     """"
#     extract techniques from wazuh alert json
#     Args:
#         json_alert: json alert from wazuh
#     Returns:
#         List of techniques
#     """
#     techniques = json_alert.get("_source").get("rule").get("mitre").get("id")
#     return techniques

# @mcp.tool()
# def find_technique(tech_id: str):
#     """
#     Query MITRE technique information by external_id (e.g. T1087.001)
#     Args:
#         tech_id: external_id of technique (e.g. T1087.001)
#     Returns:
#         information about the technique
#     """
#     repo = load_repo()
#     t = repo.find_technique_by_external_id(tech_id)

#     if not t:
#         return TextContent(type="text", text=f"Technique {tech_id} not found")
#     desc = get_full_description_from_url(t.url)
#     result = {
#         "id": t.external_id,
#         "name": t.name,
#         "description": t.description,
#         "url": t.url,
#         "phase": t.phase,
#         "groups": [[g.name, g.description] for g in t.groups[:5]],
#         "malwares": [[m.name, m.description] for m in t.malwares[:5]],
#         "tools": [[x.external_id, x.description] for x in t.tools[:5]],
#         "mitigations": [[m.name, m.description] for m in t.mitigations[:5]],
#         "campaigns": [[c.name, c.description] for c in t.campaigns[:5]],
#         "detection": desc,
#         "platforms": t.platforms,
#         "data_sources": t.data_sources,
#     }

#     return TextContent(
#         type="text",
#         text=json.dumps(result, indent=2, ensure_ascii=False)
#     )

# #======= cHECK FILE ======================
# def check_file_vt_info(file_hash):
#     """
#     Check a file hash on VirusTotal and normalize the output
#     so that it can be used by other evaluation criteria.

#     Args:
#     file_hash: The file hash to check

#     Returns:
#         A dictionary containing:
#         - crit1: VirusTotal evaluation status
#         - name: Suggested file name
#         - malicious: Number of malicious detections
#         - suspicious: Number of suspicious detections   
#         - threat: Common threat label
#         - vt_raw: Raw data returned from VirusTotal
#     """
#     vt = virustotal_check_file_hash(file_hash)

#     if "error" in vt:
#         return {"crit1": "Không kiểm tra được VirusTotal", "detail": vt}

#     stats = vt.get("last_analysis_stats", {})
#     malicious = stats.get("malicious", 0)
#     suspicious = stats.get("suspicious", 0)
#     name = vt.get("meaningful_name")
#     threat = vt.get("popular_threat_classification", {}).get("suggested_threat_label")

#     # Trả về dữ liệu sạch để tiêu chí khác dùng
#     return {
#         "crit1": "OK",
#         "name": name,
#         "malicious": malicious,
#         "suspicious": suspicious,
#         "threat": threat,
#         "vt_raw": vt
#     }

# def check_file_path(path):
#     """
#     Check whether a file path is located inside a sensitive directory
#     and whether it has a dangerous executable extension.

#     Args:
#         path: The file path

#     Returns:
#         A dictionary containing crit2: "OK" or a warning indicating that an executable file is located in a sensitive directory.
#     """
#     path_lc = path.lower()

#     dangerous_exts = [".exe", ".dll", ".bat", ".cmd", ".vbs", ".js", ".ps1", ".sh"]
#     suspicious_dirs = [
#         "c:/", "windows/system32", "windows/syswow64", "programdata",
#         "program files", "appdata", "localappdata", "users/public", "temp"
#     ]

#     _, ext = os.path.splitext(path_lc)

#     in_sensitive_dir = any(i in path_lc.replace("\\", "/") for i in suspicious_dirs)
#     is_exec = ext in dangerous_exts

#     if in_sensitive_dir and is_exec:
#         return {"crit2": "File thực thi nằm trong thư mục nhạy cảm"}

#     return {"crit2": "OK"}

# def check_filename_reputation(name):
#     """
#     Check whether the file name contains dangerous keywords such as
#     crack, malware, trojan, etc.

#     Args:
#     name: The file name

#     Returns:
#     A dictionary containing crit3: "OK" or a warning indicating a suspicious file name.
#     """
#     if not name:
#         return {"crit3": "Không có tên file từ VT"}

#     name_lc = name.lower()

#     bad_keywords = ["crack", "keygen", "loader", "stealer", "infostealer",
#                     "rat", "backdoor", "trojan", "malware", "hacker"]

#     if any(k in name_lc for k in bad_keywords):
#         return {"crit3": f"Tên file đáng ngờ: {name}"}

#     return {"crit3": "OK"}

# def get_user_from_wazuh_logs(filename: str):
#     """
#     Query Wazuh OpenSearch logs to identify the user who created the file.
#     Supported sources:
#         Windows Sysmon/EventLog
#         Linux Auditd (username or AUID)

#     Args:
#         filename: The file name

#     Returns:
#     A dictionary containing:
#         type: "windows" or "linux"
#         user: The username or UID
#         status: Search status
#         raw: Raw logs returned from Wazuh
#     """

#     query = f"*{filename}*"
#     alerts = search_alerts(query, size=100)

#     if not alerts:
#         return {"user": None, "log": None, "status": "No logs found"}

#     results = []

#     for alert in alerts:

#         # ======================
#         # 1. Windows Sysmon (Process Create, File Create, etc.)
#         # ======================
#         try:
#             eventdata = (
#                 alert.get("log", {})
#                      .get("data", {})
#                      .get("win", {})
#                      .get("eventdata", {})
#             )

#             # Nếu có eventdata => đây là log Windows Sysmon
#             if eventdata:

#                 info = {
#                     "type": "windows",
#                     "user": eventdata.get("user"),
#                     "uid": eventdata.get("logonId"),
#                     "logon_guid": eventdata.get("logonGuid"),
#                     "process": eventdata.get("image"),
#                     "parent_process": eventdata.get("parentImage"),
#                     "command_line": eventdata.get("commandLine"),
#                     "raw": alert
#                 }
#                 results.append(info)
#                 continue  # sang alert tiếp theo

#         except Exception as e:
#             print(f"Windows parse error: {e}")

#         # ======================
#         # 2. Linux Auditd – user name
#         # ======================
#         user_linux = (
#             alert.get("data", {})
#                  .get("user", {})
#                  .get("name")
#         )
#         if user_linux:
#             results.append({
#                 "type": "linux",
#                 "user": user_linux,
#                 "status": "Linux User Found",
#                 "raw": alert
#             })
#             continue

#         # ======================
#         # 3. Linux Auditd – AUID
#         # ======================
#         auid = (
#             alert.get("data", {})
#                  .get("audit", {})
#                  .get("auid")
#         )
#         if auid:
#             results.append({
#                 "type": "linux",
#                 "user": f"UID:{auid}",
#                 "status": "Linux AUID Found",
#                 "raw": alert
#             })
#             continue

#     # =======================================
#     # Ưu tiên chọn log có user rõ ràng nhất
#     # =======================================

#     # Ưu tiên Windows có user
#     for r in results:
#         if r["type"] == "windows" and r["user"]:
#             return r

#     # Ưu tiên Linux user name
#     for r in results:
#         if r["type"] == "linux" and "User Found" in r.get("status", ""):
#             return r

#     # Nếu chỉ có AUID
#     for r in results:
#         if r["type"] == "linux" and "AUID" in r.get("status", ""):
#             return r

#     # Không xác định được user – trả lại log đầu tiên để bạn tự xem
#     return {"user": None, "log": alerts[0], "status": "User Not Found"}

# def check_file_creator_user(filename):
#     """
#     Identify the user who created the file from Wazuh logs, and issue a warning
#     if the file was created by a service account (potential exploit risk).

#     Args:
#         filename: The file name

#     Returns:
#         A dictionary containing crit4: information about the user who created the file,
#         or a warning.
#     """

#     user_info = get_user_from_wazuh_logs(filename)

#     user = user_info.get("user")

#     if not user:
#         return {"crit4": "Không xác định được user", "detail": user_info}

#     # User dịch vụ → nguy cơ exploit
#     suspicious_users = ["www-data", "apache", "nginx", "mysql", "system", "network service"]

#     if str(user).lower() in suspicious_users:
#         return {"crit4": "File do user dịch vụ tạo — có thể bị exploit", "detail": user_info}

#     return {"crit4": f"User tạo file: {user}", "detail": user_info}


# def summarize_playbook(results):
#     """
#     Aggregate the results of all file-checking criteria and produce the final conclusion.

#     Args:
#         results: A dictionary containing the outputs of crit1 → crit4

#     Returns:
#         A conclusion string (e.g., "CONFIRMED MALWARE", "HIGHLY SUSPICIOUS", ...)
#     """

#     malicious = results["crit1"].get("malicious", 0)

#     # Quy tắc đánh giá cuối
#     if malicious >= 25:
#         return "=> KẾT LUẬN: CHẮC CHẮN LÀ MÃ ĐỘC"

#     if 5 <= malicious < 25:
#         return "=> KẾT LUẬN: NGHI NGỜ MẠNH (Có thể là crack/hacktool)"

#     if results["crit2"] != "OK":
#         return "=> KẾT LUẬN: File thực thi trong thư mục nhạy cảm → nguy cơ cao"

#     if "đáng ngờ" in results["crit3"].lower():
#         return "=> KẾT LUẬN: Tên file nguy hiểm → cần phân tích thêm"

#     if "exploit" in results["crit4"].lower():
#         return "=> KẾT LUẬN: File được tạo bởi user dịch vụ → nguy cơ bị tấn công"

#     return "=> KẾT LUẬN: KHÔNG ĐỦ DỮ LIỆU, ĐỀ XUẤT TẢI FILE VỀ PHÂN TÍCH"

# @mcp.tool()
# def check_file_playbook(file_hash, path):
#     """
#     Execute the complete file analysis playbook:
#         1. VirusTotal scan
#         2. Sensitive file path check
#         3. Suspicious file name check
#         4. File creator user check
#         5. Final conclusion aggregation

#     Args:
#         file_hash: The hash of the file to be analyzed
#         path: The file path on the system

#     Returns:
#         A dictionary containing the aggregated results, including crit1 → crit4
#         and the final conclusion.
#     """

#     result = {}

#     # tiêu chí 1
#     r1 = check_file_vt_info(file_hash)
#     result["crit1"] = r1

#     # tiêu chí 2
#     r2 = check_file_path(path)
#     result["crit2"] = r2["crit2"]

#     # tiêu chí 3
#     r3 = check_filename_reputation(r1.get("name"))
#     result["crit3"] = r3["crit3"]

#     # tiêu chí 4
#     filename = os.path.basename(path)
#     r4 = check_file_creator_user(filename)
#     result["crit4"] = r4["crit4"]

#     # tiêu chí 5
#     conclusion = summarize_playbook(result)
#     result["conclusion"] = conclusion

#     return result

# #============= CHECK FILE END ==================

# #============= CHECK DOMAIN ==============
# @mcp.tool()
# def evaluate_domain_playbook(domain: str):
#     """
#     Assess the risk level of a domain based on the following criteria:
#     1. VirusTotal
#     2. Domain name pattern
#     3. Google presence (basic heuristic)
#     4. HTTP access test
#     """

#     # print(f"\n=== RESULT FOR DOMAIN: {domain} ===")

#     # Normalize domain
#     parsed = urlparse(domain)
#     if parsed.netloc:
#         domain = parsed.netloc

#     # -----------------------
#     # 1. CHECK VIRUSTOTAL
#     # -----------------------
#     vt_data = virustotal_check_domain(domain)

#     score = 0
#     details = []

#     if "error" in vt_data:
#         return {"error": vt_data["error"]}

#     malicious = vt_data.get("last_analysis_stats", {}).get("malicious", 0)
#     suspicious = vt_data.get("last_analysis_stats", {}).get("suspicious", 0)

#     # AV detection count
#     if malicious >= 3:
#         score += 3
#         details.append("[VT] ≥3 AV báo malicious → nghi cao")
#     elif 1 <= malicious < 3:
#         score += 1
#         details.append("[VT] 1–2 AV báo malicious → nghi nhẹ")
#     else:
#         details.append("[VT] 0 AV báo → khả năng sạch")

#     # Creation Date
#     creation_ts = vt_data.get("creation_date")
#     if creation_ts:
#         cd_days = (datetime.datetime.utcnow() - 
#                   datetime.datetime.utcfromtimestamp(creation_ts)).days
#         if cd_days < 30:
#             score += 1
#             details.append("[VT] Domain mới <30 ngày → rủi ro cao")
#         else:
#             details.append("[VT] Domain lâu năm → tăng độ tin cậy")

#     # Popular Rank
#     if vt_data.get("popularity_ranks"):
#         details.append("[VT] Có Popular Rank → tăng uy tín")
#     else:
#         score += 1
#         details.append("[VT] Không có Popular Rank → nghi ngờ")

#     # -----------------------------------
#     # 2. DOMAIN NAME HEURISTICS
#     # -----------------------------------
#     suspicious_keywords = ["login", "verify", "secure", "update"]
#     if any(k in domain.lower() for k in suspicious_keywords):
#         score += 2
#         details.append("[NAME] Domain chứa keyword nhạy cảm")

#     known_brands = ["google", "facebook", "microsoft", "apple", "amazon", "dantri", "vnexpress"]
#     for brand in known_brands:
#         if brand in domain.lower() and not domain.lower().startswith(brand):
#             score += 3
#             details.append("[NAME] Typosquatting theo thương hiệu → nghi cao")

#     # -----------------------------------
#     # 3. GOOGLE CHECK (HEURISTIC ONLY)
#     # -----------------------------------
#     # No Google API used → heuristic fallback
#     if "." not in domain:
#         score += 1
#         details.append("[GOOGLE] Domain không hợp lệ → nghi ngờ")
#     else:
#         details.append("[GOOGLE] Bỏ qua kiểm tra Google API")

#     # -----------------------------------
#     # 4. HTTP ACCESS TEST
#     # -----------------------------------
#     try:
#         r = requests.get("http://" + domain, timeout=5)
#         if r.status_code == 200:
#             details.append("[HTTP] Website truy cập được → có thể sạch")
#         else:
#             score += 1
#             details.append("[HTTP] HTTP trả mã lỗi → nghi ngờ")
#     except:
#         score += 2
#         details.append("[HTTP] Không truy cập được → nguy cơ C2/botnet cao")

#     # -----------------------------------
#     # FINAL DECISION
#     # -----------------------------------
#     if score >= 6:
#         verdict = "MALICIOUS"
#     elif 3 <= score < 6:
#         verdict = "SUSPICIOUS"
#     else:
#         verdict = "CLEAN"

#     return {
#         "domain": domain,
#         "score": score,
#         "verdict": verdict,
#         "details": details
#         # "virustotal_data": vt_data
#     }
# #============= CHECK DOMAIN END ==============

# #============= CHECK IP ==============
# def check_ip_vpn(ip: str):
#     """
#     Check if an IP is a VPN/proxy using ip2location proxy addon
#     Args:
#         ip: IP address to check (e.g., '
#     """

#     url = f"https://api.ip2location.io/?key={IP2LOCATION_API_KEY}&ip={ip}&addon=all"
#     resp = requests.get(url, timeout=5)
#     resp.raise_for_status()
#     data = resp.json()
#     # kiểm tra trường proxy
#     proxy_info = data.get("proxy", {})
#     is_vpn = proxy_info.get("is_vpn", False)
#     return {
#         "ip": ip,
#         "is_vpn": is_vpn,
#         "proxy_type": proxy_info.get("proxy_type"),
#         "full_info": data
#     }

# @mcp.tool()
# def evaluate_ip_threat(ip: str):
#     """
#     Evaluate an IP according to the playbook, returning only the results of the criteria 
#     (without including raw data).

#     Args:
#         ip: The IP address to be evaluated
#     """


#     result = {
#         "ip": ip,
#         "criteria": {
#             "domain_resolution": None,
#             "virustotal": {},
#             "crowdsource": None,
#             "relations": None,
#             "abuseipdb": {},
#             "ip2location": {},
#             "vpn_check": None
#         },
#         "verdict": "UNKNOWN",
#         "reason": []
#     }

#     # ======================================================
#     # 0) DOMAIN RESOLUTION (Ưu tiên cao nhất)
#     # ======================================================
#     vt = virustotal_check_ip(ip)
#     vt_attr = vt if isinstance(vt, dict) else {}

#     vt_dns = vt_attr.get("last_dns_records", [])
#     resolved_domains = [d.get("value") for d in vt_dns if d.get("value")]

#     if len(resolved_domains) > 100:
#         # nhiều domain con → hosting
#         roots = {dom.split(".")[-2:] for dom in resolved_domains if "." in dom}
#         if len(roots) > 10:
#             result["criteria"]["domain_resolution"] = "hosting"
#             result["verdict"] = "CLEAN"
#             result["reason"].append("IP resolve > 100 domain khác nhau → hosting → sạch.")
#             return result
#     else:
#         result["criteria"]["domain_resolution"] = "normal"

#     # ======================================================
#     # 1) VIRUSTOTAL
#     # ======================================================
#     stats = vt_attr.get("last_analysis_stats", {})
#     malicious = stats.get("malicious", 0)
#     community_score = vt_attr.get("reputation", 0)

#     vt_result = "clean"
#     if malicious >= 3:
#         vt_result = "malicious"
#     elif 0 < malicious < 3:
#         vt_result = "low_suspicious"

#     result["criteria"]["virustotal"] = {
#         "malicious_av": malicious,
#         "community_score": community_score,
#         "result": vt_result
#     }

#     # ======================================================
#     # 2) CROWDSOURCE
#     # ======================================================
#     if vt_attr.get("crowdsourced_context"):
#         result["criteria"]["crowdsource"] = "has_context"
#     else:
#         result["criteria"]["crowdsource"] = "no_context"

#     # ======================================================
#     # 3) RELATIONS
#     # ======================================================
#     relations = vt_attr.get("last_analysis_results", {})
#     malicious_engines = [
#         e for e, d in relations.items() if d.get("category") == "malicious"
#     ]

#     if len(malicious_engines) > 5:
#         result["criteria"]["relations"] = "many_malicious_relations"
#     elif len(malicious_engines) > 0:
#         result["criteria"]["relations"] = "some_malicious_relations"
#     else:
#         result["criteria"]["relations"] = "clean_relations"

#     # ======================================================
#     # 4) ABUSEIPDB
#     # ======================================================
#     abuse = abuseipdb_check_ip(ip)
#     if isinstance(abuse, dict):
#         score = abuse.get("abuseConfidenceScore", 0)
#         if score > 75:
#             result["criteria"]["abuseipdb"] = {"score": score, "result": "malicious"}
#         elif score > 25:
#             result["criteria"]["abuseipdb"] = {"score": score, "result": "suspicious"}
#         else:
#             result["criteria"]["abuseipdb"] = {"score": score, "result": "clean"}
#     else:
#         result["criteria"]["abuseipdb"] = {"score": None, "result": "unknown"}

#     # ======================================================
#     # 5) IP2LOCATION — ISP / COUNTRY
#     # ======================================================
#     ip2 = check_ip2location(ip)
#     country = ip2.get("country_code", None)
#     isp = ip2.get("isp", "").lower()

#     isp_status = "unknown"
#     if any(x in isp for x in ["google", "microsoft", "amazon", "akamai", "cloudflare"]):
#         isp_status = "high_trust"
#     elif "viettel" in isp or "vnpt" in isp or "fpt" in isp:
#         isp_status = "vn_local"

#     result["criteria"]["ip2location"] = {
#         "country": country,
#         "isp_reputation": isp_status
#     }

#     # ======================================================
#     # 6) VPN / Proxy check
#     # ======================================================
#     vpn_info = check_ip_vpn(ip)
#     if vpn_info.get("is_vpn"):
#         result["criteria"]["vpn_check"] = "vpn"
#     else:
#         result["criteria"]["vpn_check"] = "not_vpn"

#     # ======================================================
#     # FINAL VERDICT
#     # ======================================================

#     # ---- Playbook Rules ----
#     if country == "VN":
#         result["reason"].append("IP thuộc Việt Nam → không tác động nếu không có bằng chứng mạnh.")

#     if result["criteria"]["virustotal"]["result"] == "malicious":
#         result["verdict"] = "MALICIOUS"
#         result["reason"].append(">= 3 AV phát hiện độc.")

#     elif result["criteria"]["abuseipdb"]["result"] == "malicious":
#         result["verdict"] = "MALICIOUS"
#         result["reason"].append("AbuseIPDB score > 75.")

#     elif result["criteria"]["vpn_check"] == "vpn":
#         result["verdict"] = "SUSPICIOUS"
#         result["reason"].append("IP là VPN.")

#     elif result["criteria"]["virustotal"]["result"] == "low_suspicious":
#         result["verdict"] = "SUSPICIOUS"
#         result["reason"].append("Có AV báo nhưng ít.")

#     elif result["criteria"]["virustotal"]["result"] == "clean" and \
#          result["criteria"]["abuseipdb"]["result"] == "clean" and \
#          result["criteria"]["vpn_check"] == "not_vpn":
#         result["verdict"] = "CLEAN"
#         result["reason"].append("Không có dấu hiệu độc hại.")

#     else:
#         result["verdict"] = "SUSPICIOUS"
#         result["reason"].append("Không đủ bằng chứng để kết luận.")

#     return result


# if __name__ == "__main__":
#     print(f"Starting Wazuh MCP server on {BASE_URL}...")
#     print(f"VirusTotal API: {'Configured' if VIRUSTOTAL_API_KEY else 'Not configured'}")
#     print(f"AbuseIPDB API: {'Configured' if ABUSEIPDB_API_KEY else 'Not configured'}")
#     mcp.run()

from dotenv import load_dotenv
import os

import os
import requests
import json
import re
import base64
from fastmcp import FastMCP
from requests.auth import HTTPBasicAuth

from dotenv import load_dotenv
import os
import datetime
from urllib.parse import urlparse

# ============================================
# CÂU HÌNH CHUNG
# ============================================
load_dotenv()
WAZUH_HOST = os.getenv("WAZUH_HOST")
WAZUH_PORT = os.getenv("WAZUH_PORT")
WAZUH_USER = os.getenv("WAZUH_USER")
WAZUH_PASS = os.getenv("WAZUH_PASS")
ALLOW_SELF_SIGNED = os.getenv("WAZUH_ALLOW_SELF_SIGNED", "true").lower() == "true"
VERIFY_SSL = not ALLOW_SELF_SIGNED
BASE_URL = f"{WAZUH_HOST}:{WAZUH_PORT}"

# === Threat Intelligence APIs ===
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"
IP2LOCATION_API_KEY = os.getenv("IP2LOCATION_API_KEY")

mcp = FastMCP("opensearch-mcp-server")
# === Helper: Get JWT token ===
def get_wazuh_token():
    url = f"{BASE_URL}/security/user/authenticate"
    resp = requests.get(url, auth=(WAZUH_USER, WAZUH_PASS), verify=VERIFY_SSL)
    if resp.status_code != 200:
        raise Exception(f"Auth failed: {resp.text}")
    return resp.json()["data"]["token"]

# ============================================
# CÁC HÀM KIỂM TRA IP
# ============================================

def virustotal_check_ip(ip: str):
    """Check an IP address reputation on VirusTotal.
    
    Args:
        ip: IP address to check (e.g., '8.8.8.8')
    
    Returns:
        Dict with reputation, malicious detections, country, ASN, etc.
    """
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VIRUSTOTAL_API_KEY not set in environment"}
    
    try:
        headers = {
            "accept": "application/json",
            "x-apikey": VIRUSTOTAL_API_KEY
            }
        response = requests.get(
            f"{VIRUSTOTAL_BASE_URL}/ip_addresses/{ip}",
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json().get("data", {})
            attributes = data.get("attributes", {})
            return attributes

        elif response.status_code == 404:
            return {"ip": ip, "verdict": "NOT_FOUND", "message": "IP not found in VirusTotal database"}
        else:
            return {"error": f"VT API error {response.status_code}: {response.text}"}
    except Exception as e:
        return {"error": str(e)}
    
def abuseipdb_check_ip(ip: str):
    """Check IP reputation on AbuseIPDB.
    
    Args:
        ip: IP address to check (e.g., '1.2.3.4')
    
    Returns:
        Dict with abuse confidence score, reports, country, ISP, etc.
    """
    if not ABUSEIPDB_API_KEY:
        return {"error": "ABUSEIPDB_API_KEY not set in environment"}
    
    try:
        headers = {
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": ""
        }
        
        response = requests.get(
            f"{ABUSEIPDB_BASE_URL}/check",
            headers=headers,
            params=params
        )
        
        if response.status_code == 200:
            data = response.json().get("data", {})
            with open("abuseipdb_response.json", "w") as f:
                json.dump(data, f, indent=4)
            return data
        else:
            return {"error": f"AbuseIPDB API error {response.status_code}: {response.text}"}
    except Exception as e:
        return {"error": str(e)}

def check_ip2location(ip: str):
    """Check IP geolocation using ip2location 
    Args:
        ip: IP address to check (e.g., '
    """
    try:
        # print(IP2LOCATION_API_KEY)
        response = requests.get(f"https://api.ip2location.io/?key={IP2LOCATION_API_KEY}&ip={ip}&format=json")
        if response.status_code == 200:
            data = response.json()
            with open("ip2location_response.json", "w") as f:
                json.dump(data, f, indent=4)
            return data
        else:
            return {"error": f"ip2location API error {response.status_code}: {response.text}"}
    except Exception as e:
        return {"error": str(e)}
    
def check_ip_vpn(ip: str) -> dict:
    """
    Check if an IP is a VPN/proxy using ip2location proxy addon
    Args:
        ip: IP address to check (e.g., '
    """

    url = f"https://api.ip2location.io/?key={IP2LOCATION_API_KEY}&ip={ip}&addon=all"
    resp = requests.get(url, timeout=5)
    resp.raise_for_status()
    data = resp.json()
    # kiểm tra trường proxy
    proxy_info = data.get("proxy", {})
    is_vpn = proxy_info.get("is_vpn", False)
    return {
        "ip": ip,
        "is_vpn": is_vpn,
        "proxy_type": proxy_info.get("proxy_type"),
        "full_info": data
    }

@mcp.tool
def evaluate_ip_threat(ip: str) -> dict:
    """Đánh giá IP theo playbook, chỉ trả về kết quả các tiêu chí (không chứa raw data)."""

    result = {
        "ip": ip,
        "criteria": {
            "isp": None,
            "domain_resolution": None,
            "virustotal": {},
            "crowdsource": None,
            "relations": None,
            "abuseipdb": {},
            "ip2location": {},
            "vpn_check": None
        },
        "verdict": "UNKNOWN",
        "reason": []
    }

    # ======================================================
    # 0) DOMAIN RESOLUTION (Ưu tiên cao nhất)
    # ======================================================
    vt = virustotal_check_ip(ip)
    vt_attr = vt if isinstance(vt, dict) else {}

    vt_dns = vt_attr.get("last_dns_records", [])
    resolved_domains = [d.get("value") for d in vt_dns if d.get("value")]

    if len(resolved_domains) > 100:
        # nhiều domain con → hosting
        roots = {dom.split(".")[-2:] for dom in resolved_domains if "." in dom}
        if len(roots) > 10:
            result["criteria"]["domain_resolution"] = "hosting"
            result["verdict"] = "CLEAN"
            result["reason"].append("IP resolve > 100 domain khác nhau → hosting → sạch.")
            return result
    else:
        result["criteria"]["domain_resolution"] = "normal"

    # ======================================================
    # 1) VIRUSTOTAL
    # ======================================================
    stats = vt_attr.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    community_score = vt_attr.get("reputation", 0)

    vt_result = "clean"
    if malicious >= 3:
        vt_result = "malicious"
    elif 0 < malicious < 3:
        vt_result = "low_suspicious"

    result["criteria"]["virustotal"] = {
        "malicious_av": malicious,
        "community_score": community_score,
        "result": vt_result
    }

    # ======================================================
    # 2) CROWDSOURCE
    # ======================================================
    if vt_attr.get("crowdsourced_context"):
        result["criteria"]["crowdsource"] = "has_context"
    else:
        result["criteria"]["crowdsource"] = "no_context"

    # ======================================================
    # 3) RELATIONS
    # ======================================================
    relations = vt_attr.get("last_analysis_results", {})
    malicious_engines = [
        e for e, d in relations.items() if d.get("category") == "malicious"
    ]

    if len(malicious_engines) > 5:
        result["criteria"]["relations"] = "many_malicious_relations"
    elif len(malicious_engines) > 0:
        result["criteria"]["relations"] = "some_malicious_relations"
    else:
        result["criteria"]["relations"] = "clean_relations"

    # ======================================================
    # 4) ABUSEIPDB
    # ======================================================
    abuse = abuseipdb_check_ip(ip)
    if isinstance(abuse, dict):
        score = abuse.get("abuseConfidenceScore", 0)
        if score > 75:
            result["criteria"]["abuseipdb"] = {"score": score, "result": "malicious"}
        elif score > 25:
            result["criteria"]["abuseipdb"] = {"score": score, "result": "suspicious"}
        else:
            result["criteria"]["abuseipdb"] = {"score": score, "result": "clean"}
    else:
        result["criteria"]["abuseipdb"] = {"score": None, "result": "unknown"}

    # ======================================================
    # 5) IP2LOCATION — ISP / COUNTRY
    # ======================================================
    ip2 = check_ip2location(ip)
    country = ip2.get("country_code", None)
    isp = ip2.get("isp", "").lower()
    result["criteria"]["isp"] = isp

    isp_status = "unknown"
    if any(x in isp for x in ["google", "microsoft", "amazon", "akamai", "cloudflare"]):
        isp_status = "high_trust"
    elif "viettel" in isp or "vnpt" in isp or "fpt" in isp:
        isp_status = "vn_local"

    result["criteria"]["ip2location"] = {
        "country": country,
        "isp_reputation": isp_status
    }

    # ======================================================
    # 6) VPN / Proxy check
    # ======================================================
    vpn_info = check_ip_vpn(ip)
    if vpn_info.get("is_vpn"):
        result["criteria"]["vpn_check"] = "vpn"
    else:
        result["criteria"]["vpn_check"] = "not_vpn"

    # ======================================================
    # FINAL VERDICT
    # ======================================================

    # ---- Playbook Rules ----
    if country == "VN":
        result["reason"].append("IP thuộc Việt Nam → không tác động nếu không có bằng chứng mạnh.")

    if result["criteria"]["virustotal"]["result"] == "malicious":
        result["verdict"] = "MALICIOUS"
        result["reason"].append(">= 3 AV phát hiện độc.")

    elif result["criteria"]["abuseipdb"]["result"] == "malicious":
        result["verdict"] = "MALICIOUS"
        result["reason"].append("AbuseIPDB score > 75.")

    elif result["criteria"]["vpn_check"] == "vpn":
        result["verdict"] = "SUSPICIOUS"
        result["reason"].append("IP là VPN.")

    elif result["criteria"]["virustotal"]["result"] == "low_suspicious":
        result["verdict"] = "SUSPICIOUS"
        result["reason"].append("Có AV báo nhưng ít.")

    elif result["criteria"]["virustotal"]["result"] == "clean" and \
         result["criteria"]["abuseipdb"]["result"] == "clean" and \
         result["criteria"]["vpn_check"] == "not_vpn":
        result["verdict"] = "CLEAN"
        result["reason"].append("Không có dấu hiệu độc hại.")

    else:
        result["verdict"] = "SUSPICIOUS"
        result["reason"].append("Không đủ bằng chứng để kết luận.")

    return result
# print(evaluate_ip_threat("52.123.129.14"))
# ============================================
# CÁC HÀM KIỂM TRA DOMAIN
# ============================================
import socket

def resolve_domain_from_ip(ip: str):
    try:
        host, alias, _ = socket.gethostbyaddr(ip)
        return host  # domain trả về
    except Exception:
        return None
    
def virustotal_check_domain(domain: str):
    """Check a domain reputation on VirusTotal.
    
    Args:
        domain: Domain to check (e.g., 'google.com')
    
    Returns:
        Dict with reputation, malicious detections, categories, etc.
    """
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VIRUSTOTAL_API_KEY not set in environment"}
    
    try:
        headers = {
            "accept": "application/json",
            "x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(
            f"{VIRUSTOTAL_BASE_URL}/domains/{domain}",
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json().get("data", {})
            attributes = data.get("attributes", {})
            # with open("check_domain_result.json", "w") as f:
            #     json.dump(attributes, f, indent=4)
            return attributes

        elif response.status_code == 404:
            return {"domain": domain, "verdict": "NOT_FOUND", "message": "Domain not found in VirusTotal database"}
        else:
            return {"error": f"VT API error {response.status_code}: {response.text}"}
    except Exception as e:
        return {"error": str(e)}

@mcp.tool
def evaluate_domain_playbook(domain: str) -> dict:
    """
    Assess the risk level of a domain based on the following criteria:
    1. VirusTotal
    2. Domain name pattern
    3. Google presence (basic heuristic)
    4. HTTP access test
    """

    # print(f"\n=== RESULT FOR DOMAIN: {domain} ===")

    # Normalize domain
    parsed = urlparse(domain)
    if parsed.netloc:
        domain = parsed.netloc

    # -----------------------
    # 1. CHECK VIRUSTOTAL
    # -----------------------
    vt_data = virustotal_check_domain(domain)

    score = 0
    details = []

    if "error" in vt_data:
        return {"error": vt_data["error"]}

    malicious = vt_data.get("last_analysis_stats", {}).get("malicious", 0)
    suspicious = vt_data.get("last_analysis_stats", {}).get("suspicious", 0)

    # AV detection count
    if malicious >= 3:
        score += 3
        details.append("[VT] ≥3 AV báo malicious → nghi cao")
    elif 1 <= malicious < 3:
        score += 1
        details.append("[VT] 1–2 AV báo malicious → nghi nhẹ")
    else:
        details.append("[VT] 0 AV báo → khả năng sạch")

    # Creation Date
    creation_ts = vt_data.get("creation_date")
    if creation_ts:
        cd_days = (datetime.datetime.utcnow() - 
                  datetime.datetime.utcfromtimestamp(creation_ts)).days
        if cd_days < 30:
            score += 1
            details.append("[VT] Domain mới <30 ngày → rủi ro cao")
        else:
            details.append("[VT] Domain lâu năm → tăng độ tin cậy")

    # Popular Rank
    if vt_data.get("popularity_ranks"):
        details.append("[VT] Có Popular Rank → tăng uy tín")
    else:
        score += 1
        details.append("[VT] Không có Popular Rank → nghi ngờ")

    # -----------------------------------
    # 2. DOMAIN NAME HEURISTICS
    # -----------------------------------
    suspicious_keywords = ["login", "verify", "secure", "update"]
    if any(k in domain.lower() for k in suspicious_keywords):
        score += 2
        details.append("[NAME] Domain chứa keyword nhạy cảm")

    known_brands = ["google", "facebook", "microsoft", "apple", "amazon", "dantri", "vnexpress"]
    for brand in known_brands:
        if brand in domain.lower() and not domain.lower().startswith(brand):
            score += 3
            details.append("[NAME] Typosquatting theo thương hiệu → nghi cao")

    # -----------------------------------
    # 3. GOOGLE CHECK (HEURISTIC ONLY)
    # -----------------------------------
    # No Google API used → heuristic fallback
    if "." not in domain:
        score += 1
        details.append("[GOOGLE] Domain không hợp lệ → nghi ngờ")
    else:
        details.append("[GOOGLE] Bỏ qua kiểm tra Google API")

    # -----------------------------------
    # 4. HTTP ACCESS TEST
    # -----------------------------------
    try:
        r = requests.get("http://" + domain, timeout=5)
        if r.status_code == 200:
            details.append("[HTTP] Website truy cập được → có thể sạch")
        else:
            score += 1
            details.append("[HTTP] HTTP trả mã lỗi → nghi ngờ")
    except:
        score += 2
        details.append("[HTTP] Không truy cập được → nguy cơ C2/botnet cao")

    # -----------------------------------
    # FINAL DECISION
    # -----------------------------------
    if score >= 6:
        verdict = "MALICIOUS"
    elif 3 <= score < 6:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return {
        "domain": domain,
        "score": score,
        "verdict": verdict,
        "details": details
        # "virustotal_data": vt_data
    }
# print(evaluate_domain_playbook("facebook.com"))
# ============================================
# CÁC HÀM KIỂM TRA FILE
# ============================================
def virustotal_check_file_hash(file_hash: str):
    """Check a file hash (MD5, SHA1, or SHA256) on VirusTotal.
    
    Args:
        file_hash: File hash to check (MD5/SHA1/SHA256)
    
    Returns:
        Dict with file info, malicious detections, reputation, etc.
    """
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VIRUSTOTAL_API_KEY not set in environment"}
    
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(
            f"{VIRUSTOTAL_BASE_URL}/files/{file_hash}",
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json().get("data", {})
            attributes = data.get("attributes", {})
            return attributes

        elif response.status_code == 404:
            return {"hash": file_hash, "verdict": "NOT_FOUND", "message": "Hash not found in VirusTotal database"}
        else:
            return {"error": f"VT API error {response.status_code}: {response.text}"}
    except Exception as e:
        return {"error": str(e)}

def check_file_vt_info(file_hash):
    """
    Kiểm tra hash file trên VirusTotal và chuẩn hóa dữ liệu đầu ra
    để các tiêu chí khác có thể sử dụng.

    Args:
        file_hash: Hash file

    Returns:
        Dict gồm:
            - crit1: trạng thái kiểm tra VT
            - name: tên file gợi ý
            - malicious: số phát hiện độc hại
            - suspicious: số phát hiện đáng ngờ
            - threat: nhãn mối đe dọa phổ biến
            - vt_raw: dữ liệu thô từ VT
    """
    vt = virustotal_check_file_hash(file_hash)

    if "error" in vt:
        return {"crit1": "Không kiểm tra được VirusTotal", "detail": vt}

    stats = vt.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    name = vt.get("meaningful_name")
    threat = vt.get("popular_threat_classification", {}).get("suggested_threat_label")

    # Trả về dữ liệu sạch để tiêu chí khác dùng
    return {
        "crit1": "OK",
        "name": name,
        "malicious": malicious,
        "suspicious": suspicious,
        "threat": threat,
        "vt_raw": vt
    }

def check_filename_reputation(name):
    """
    Kiểm tra tên file xem có chứa từ khóa nguy hiểm, crack, malware, trojan,...

    Args:
        name: tên file

    Returns:
        Dict với crit3: "OK" hoặc cảnh báo tên file đáng ngờ
    """
    if not name:
        return {"crit3": "Không có tên file từ VT"}

    name_lc = name.lower()

    bad_keywords = ["crack", "keygen", "loader", "stealer", "infostealer",
                    "rat", "backdoor", "trojan", "malware", "hacker"]

    if any(k in name_lc for k in bad_keywords):
        return {"crit3": f"Tên file đáng ngờ: {name}"}

    return {"crit3": "OK"}

def get_user_from_wazuh_logs(filename: str):
    """
    Truy vấn Wazuh OpenSearch logs để tìm user tạo file.

    Hỗ trợ:
        - Windows Sysmon/EventLog
        - Linux Auditd (tên user hoặc AUID)

    Args:
        filename: tên file

    Returns:
        Dict chứa:
            - type: "windows" hoặc "linux"
            - user: tên user hoặc UID
            - status: trạng thái tìm kiếm
            - raw: log thô từ Wazuh
    """

    query = f"*{filename}*"
    alerts = search_alerts(query, size=100)

    if not alerts:
        return {"user": None, "log": None, "status": "No logs found"}

    results = []

    for alert in alerts:

        # ======================
        # 1. Windows Sysmon (Process Create, File Create, etc.)
        # ======================
        try:
            eventdata = (
                alert.get("log", {})
                     .get("data", {})
                     .get("win", {})
                     .get("eventdata", {})
            )

            # Nếu có eventdata => đây là log Windows Sysmon
            if eventdata:

                info = {
                    "type": "windows",
                    "user": eventdata.get("user"),
                    "uid": eventdata.get("logonId"),
                    "logon_guid": eventdata.get("logonGuid"),
                    "process": eventdata.get("image"),
                    "parent_process": eventdata.get("parentImage"),
                    "command_line": eventdata.get("commandLine"),
                    "raw": alert
                }
                results.append(info)
                continue  # sang alert tiếp theo

        except Exception as e:
            print(f"Windows parse error: {e}")

        # ======================
        # 2. Linux Auditd – user name
        # ======================
        user_linux = (
            alert.get("data", {})
                 .get("user", {})
                 .get("name")
        )
        if user_linux:
            results.append({
                "type": "linux",
                "user": user_linux,
                "status": "Linux User Found",
                "raw": alert
            })
            continue

        # ======================
        # 3. Linux Auditd – AUID
        # ======================
        auid = (
            alert.get("data", {})
                 .get("audit", {})
                 .get("auid")
        )
        if auid:
            results.append({
                "type": "linux",
                "user": f"UID:{auid}",
                "status": "Linux AUID Found",
                "raw": alert
            })
            continue

    # =======================================
    # Ưu tiên chọn log có user rõ ràng nhất
    # =======================================

    # Ưu tiên Windows có user
    for r in results:
        if r["type"] == "windows" and r["user"]:
            return r

    # Ưu tiên Linux user name
    for r in results:
        if r["type"] == "linux" and "User Found" in r.get("status", ""):
            return r

    # Nếu chỉ có AUID
    for r in results:
        if r["type"] == "linux" and "AUID" in r.get("status", ""):
            return r

    # Không xác định được user – trả lại log đầu tiên để bạn tự xem
    return {"user": None, "log": alerts[0], "status": "User Not Found"}

def check_file_creator_user(filename):
    """
    Xác định user tạo file từ Wazuh logs, đồng thời cảnh báo
    nếu file do user dịch vụ (nguy cơ exploit) tạo.

    Args:
        filename: tên file

    Returns:
        Dict với crit4: thông tin user tạo file hoặc cảnh báo
    """
    check = "OK"
    user_info = get_user_from_wazuh_logs(filename)

    user = user_info.get("user")

    if not user:
        return {"crit4": "Không xác định được user", "detail": user_info, "check": "Undefined"}

    # User dịch vụ → nguy cơ exploit
    suspicious_users = [
        # Linux service users
        "www-data", "apache", "nginx", "mysql", "postgres", "mongodb",
        "ftp", "sshd", "daemon", "nobody",

        # Windows builtin service accounts (đã bỏ SYSTEM)
        "localservice", "nt authority\\local service",
        "networkservice", "nt authority\\network service",

        # Windows server components
        "trustedinstaller", "iis apppool\\defaultapppool",
        "sqlserveragent", "ms_sqlserver",

        # Common low-privilege or background accounts
        "defaultaccount", "guest", "wdagutilityaccount"
    ]

    if str(user).lower() in suspicious_users:
        check = "Malicious"
        return {"crit4": "File do user dịch vụ tạo — có thể bị exploit", "detail": user_info, }

    return {"crit4": f"User tạo file: {user}", "detail": user_info, "check": check}
def summarize_playbook(results):
    """
    Tổng hợp kết quả các tiêu chí kiểm tra file và đưa ra kết luận cuối.
    """
    malicious = results["crit1"].get("malicious", 0)

    # ✅ Sửa: kiểm tra crit2 đúng cách
    crit2_suspicious = False
    if isinstance(results["crit2"], dict):
        crit2_suspicious = results["crit2"].get("is_suspicious", False)
    elif isinstance(results["crit2"], bool):
        crit2_suspicious = results["crit2"]

    # Quy tắc đánh giá cuối
    if malicious >= 25:
        return "=> KẾT LUẬN: CHẮC CHẮN LÀ MÃ ĐỘC"

    elif 5 <= malicious < 25:
        return "=> KẾT LUẬN: NGHI NGỜ MẠNH (Có thể là crack/hacktool)"

    elif crit2_suspicious:  # ✅ Sửa
        return "=> KẾT LUẬN: File thực thi trong thư mục nhạy cảm → nguy cơ cao"

    elif "đáng ngờ" in results["crit3"].lower():
        return "=> KẾT LUẬN: Tên file nguy hiểm → cần phân tích thêm"

    elif "exploit" in results["crit4"].lower():
        return "=> KẾT LUẬN: File được tạo bởi user dịch vụ → nguy cơ bị tấn công"
    
    elif malicious == 0 and not crit2_suspicious and "đáng ngờ" not in results["crit3"].lower() and "exploit" not in results["crit4"].lower():
        return "CLEAN"
    
    return "=> KẾT LUẬN: KHÔNG ĐỦ DỮ LIỆU, ĐỀ XUẤT TẢI FILE VỀ PHÂN TÍCH"

def check_file_playbook(file_hash, path) -> dict:
    """
    Thực hiện toàn bộ playbook kiểm tra file:
        1. VirusTotal
        2. Đường dẫn file nhạy cảm
        3. Tên file đáng ngờ
        4. User tạo file
        5. Tổng hợp kết luận

    Args:
        file_hash: hash file cần kiểm tra
        path: đường dẫn file trên máy

    Returns:
        Dict kết quả tổng hợp bao gồm crit1->crit4 và conclusion
    """
    result = {}

    # tiêu chí 1
    r1 = check_file_vt_info(file_hash)
    result["crit1"] = r1

    # tiêu chí 2
    r2 = is_suspicious_executable(path)
    result["crit2"] = r2

    # tiêu chí 3
    r3 = check_filename_reputation(r1.get("name"))
    result["crit3"] = r3["crit3"]

    # tiêu chí 4
    filename = os.path.basename(path)
    r4 = check_file_creator_user(filename)

    result["crit4"] = r4["crit4"]

    # tiêu chí 5
    conclusion = summarize_playbook(result)
    result["conclusion"] = conclusion

    if "CLEAN" in conclusion:
        result["final_verdict"] = "FP"
    else:
        result["final_verdict"] = "TP"
    print(result)
    return result

# print(get_user_from_wazuh_logs("floss.exe"))
#print(check_file_playbook("6d7f542ed46fcb02893a8672eb405d4b543e2a92db1ac22b5d53dbf303568b25", "C:/Users/admin/Downloads/mas_17-20230810T055912Z-001/mas_17-20230810T055912Z-001/mas_17/MAS_1.7_Password_1234/MAS_1.7/All-In-One-Version/MAS_AIO.cmd"))
# ============================================
# CHECK PROCESS MALICIOUS
# ============================================
def is_suspicious_executable(path) -> dict:
    """
    Kiểm tra đường dẫn file xem có nằm trong thư mục nhạy cảm
    và có phần mở rộng thực thi nguy hiểm hay không,
    nhưng loại trừ các file nằm trong whitelist.

    Args:
        path: đường dẫn file

    Returns:
        True nếu file đáng ngờ, False nếu an toàn
    """
    path_lc = path.lower().replace("\\\\", "/")

    # === Các phần mở rộng nguy hiểm ===
    dangerous_exts = [".exe", ".dll", ".bat", ".cmd", ".vbs", ".js", ".ps1", ".sh"]

    # === Các thư mục nhạy cảm ===
    suspicious_dirs = [
        "c:/", "windows/system32", "windows/syswow64", "programdata",
        "program files", "appdata", "localappdata", "users/public", "temp",
        "downloads"
    ]

    # === Whitelist: các đường dẫn tuyệt đối an toàn ===
    # Whitelist: các đường dẫn tuyệt đối hợp lệ
    WHITELIST_PATHS = [
        # === Windows System Files ===
        "C:/Windows/explorer.exe",
        "C:/Windows/notepad.exe",
        "C:/Windows/System32/cmd.exe",
        "C:/Windows/System32/powershell.exe",
        "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
        "C:/Windows/System32/wscript.exe",
        "C:/Windows/System32/cscript.exe",
        "C:/Windows/System32/mshta.exe",
        "C:/Windows/System32/taskmgr.exe",
        "C:/Windows/System32/services.exe",
        "C:/Windows/System32/svchost.exe",
        "C:/Windows/System32/mspaint.exe",
        "C:/Windows/System32/winlogon.exe",
        "C:/Windows/System32/explorerframe.dll",
        "C:/Windows/System32/mmc.exe",
        "C:/Windows/System32/eventvwr.exe",
        "C:/Windows/System32/control.exe",
        "C:/Windows/System32/taskschd.msc",
        "C:/Windows/System32/perfmon.exe",
        "C:/Windows/System32/regedit.exe",
        "C:/Windows/System32/services.msc",
        "C:/Windows/System32/compmgmt.msc",
        "C:/Windows/System32/secpol.msc",
        "C:/Windows/System32/dxdiag.exe",
        "C:/Windows/System32/msconfig.exe",
        "C:/Windows/System32/diskmgmt.msc",
        "C:/Windows/System32/cleanmgr.exe",
        "C:/Windows/System32/chkdsk.exe",
        "C:/Windows/System32/sfc.exe",
        "C:/Windows/System32/defrag.exe",
        "C:/Windows/System32/attrib.exe",
        "C:/Windows/System32/robocopy.exe",
        "C:/Windows/System32/net.exe",
        "C:/Windows/System32/nslookup.exe",
        "C:/Windows/System32/tracert.exe",
        "C:/Windows/System32/powershell_ise.exe",
        "C:/Windows/System32/taskkill.exe",
        "C:/Windows/System32/cmdkey.exe",
        "C:/Windows/System32/fsutil.exe",
        "C:/Windows/System32/diskpart.exe",
        "C:/Windows/System32/reg.exe",
        "C:/Windows/System32/wevtutil.exe",
        "C:/Windows/System32/wmiadap.exe",
        "C:/Windows/System32/winrm.exe",
        # Defender
        "C:/Program Files/Windows Defender/MsMpEng.exe",
        "C:/Program Files/Windows Defender/MpCmdRun.exe",
        "C:/Program Files/Windows Defender/MsSense.exe",
        "C:/Program Files/Windows Defender/NisSrv.exe",
        "C:/Program Files/Windows Defender/MSASCuiL.exe",
        "C:/Windows/System32/WindowsDefender.dll",
        # === Program Files / Safe Apps ===
        "C:/Program Files/7-Zip/7zFM.exe",
        "C:/Program Files/7-Zip/7z.exe",
        "C:/Program Files/Google/Chrome/Application/chrome.exe",
        "C:/Program Files/Mozilla Firefox/firefox.exe",
        "C:/Program Files/Microsoft Office/root/Office16/WINWORD.EXE",
        "C:/Program Files/Microsoft Office/root/Office16/EXCEL.EXE",
        "C:/Program Files/Microsoft Office/root/Office16/POWERPNT.EXE",
        "C:/Program Files/VLC/vlc.exe",
        # === Program Files (x86) ===
        "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe",
        "C:/Program Files (x86)/Mozilla Firefox/firefox.exe",
        # === Python / Java / Development Tools ===
        "C:/Python311/python.exe",
        "C:/Python311/Scripts/pip.exe",
        "C:/Program Files/Java/jdk-17/bin/java.exe",
        "C:/Program Files/Java/jdk-17/bin/javac.exe",
        # === Other common safe tools ===
        "C:/Program Files/Git/bin/git.exe",
        "C:/Program Files/Git/cmd/git.exe",
        "C:/Program Files/Wireshark/Wireshark.exe"
    ]
    # print(path_lc)
    # Loại trừ whitelist
    for safe_path in WHITELIST_PATHS:
        if path_lc.startswith("c:/programdata/microsoft/windows defender"):
            return {"is_suspicious": False, "reason": "Windows Defender path"}
        if path_lc == safe_path.lower().replace("\\", "/"):
            return {"is_suspicious": False, "reason": "Whitelisted path"}

    is_exec = any(path_lc.endswith(ext) for ext in dangerous_exts)
    in_sensitive_dir = any(dir_str in path_lc for dir_str in suspicious_dirs)

    if is_exec and in_sensitive_dir:
        return {"is_suspicious": True, "reason": "Executable in sensitive directory"}

    return {"is_suspicious": False, "reason": "Safe path"}


def check_process_malicious(process: str=None, path: str = None) -> bool:
    """
    Kiểm tra tiến trình có trong danh sách tiến trình độc hay không.
    """
    s = ['-enc', '-encodedcommand', 'frombase64string', 'base64', 'iex', 'invoke-expression', 'downloadstring', 'downloadfile', 'net.webclient', 'invoke-webrequest', 'iwr', 'wget', 'curl', 'invoke-restmethod', 'irm', '-nop', '-noprofile', '-w', 'hidden', '-windowstyle', 'hidden', '-ep', 'bypass', 'executionpolicy', 'bypass', 'unrestricted', 'add-mppreference', 'set-mppreference', 'amsiutils', 'amsi', 'disablerealtimemonitoring', 'http://', 'https://', '.hta', 'appdata\\local\\temp', '\\temp\\', '\\users\\public\\', 'bypass', 'hidden', 'base64', 'curl', 'wget', 'nohup', 'setsid', 'disown', '/tmp/', '/var/tmp/', '/dev/shm/', 'base64', '-d', 'openssl', 'enc', 'xxd', '-r', '-p', 'netsh', 'advfirewall', 'set', 'allprofiles', 'state', 'off', 'whoami', 'tasklist', 'ipconfig', 'ping', '-executionpolicy', 'bypass']
    result = False
    # ✅ Sửa: kiểm tra path có phải dict không
    if path:
        path_check = is_suspicious_executable(path)
        if isinstance(path_check, dict) and path_check.get("is_suspicious", False):
            result = True
    
    if process:
        for keyword in s:
            if keyword in process.lower():
                result = True
                break
    
    return result

# ============================================
# SEARCH ALERTS IN WAZUH
# ============================================
def search_alerts(query: str, size: int = 100):
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
    # print(hits)
    return hits
# ============================================
# GET INFORMATION ABOUT A DEVICE
# ============================================
#Lấy thông tin về hardware, processes, os, package, network treena agent
# === Hàm gọi API Wazuh ===
def wazuh_get(path, params=None) -> dict:
    token = get_wazuh_token()
    headers = {"Authorization": f"Bearer {token}"}
    url = f"{BASE_URL}{path}"
    print(f"DEBUG URL: {url}")
    resp = requests.get(url, headers=headers, params=params, verify=VERIFY_SSL)
    resp.raise_for_status()
    return resp.json()

# === Lấy toàn bộ thông tin hệ thống của agent ===
def get_agent_syscollector(agent_id):
    """
    Retrieve all system information of an agent through Wazuh's Syscollector API.

    The collected information includes:

    - os: Operating system information (Windows, Linux, etc.)
    - netiface: Network interface information      
    - netport: Open network ports on the agent
    - netproto: Network protocols in use
    - packages: Installed software packages
    - processes: Running processes
    - ports: Related/existing ports
    - hardware: Hardware information of the agent
    - hotfixes: Security patches installed on the system

    Parameters:
    agent_id (str): The ID of the agent to retrieve information from.

    Returns:
    dict: A dictionary containing the agent_id and syscollector data of each module.
    If any module API call fails, the response will include the error and the corresponding HTTP status code.

    """
    modules = [
        "os",          # thông tin hệ điều hành
        "netiface",    # card mạng
        "netport",     # cổng đang mở
        "netproto",    # giao thức mạng
        "packages",    # gói cài đặt
        "processes",   # tiến trình đang chạy
        "ports",
        "hardware", 
        "hotfixes"
    ]

    result = {"agent_id": agent_id, "syscollector": {}}

    for module in modules:
        path = f"/syscollector/{agent_id}/{module}"
        #path = f"/agents/{agent_id}/syscollector/{module}"
        try:
            data = wazuh_get(path)
            result["syscollector"][module] = data.get("data", {}).get("affected_items", [])
        except requests.HTTPError as e:
            result["syscollector"][module] = {"error": str(e), "status": e.response.status_code}
    return result
# ============================================
# PLAYBOOK FUCTIONS - CONNECT MALICIOUS IP
# ============================================
@mcp.tool
def evaluate_ip_connection_playbook(ip: str, agent_id: str = None) -> dict:
    """
    Đánh giá kết nối đến IP độc theo playbook.

    """

    result = {
        "ip": ip,
        "step1_ip_status": None,
        "step2_connection_direction": None,
        "step3_process_list": [],
        "step3_process_mal": [],
        "step3_process_analysis": None,
        "step4_frequency_analysis": None,
        "device_info": None,
        "reason": None,
        "verdict": None
    }

    # ======================================================
    #                  BƯỚC 1 – Kiểm tra IP độc
    # ======================================================
    step1 = evaluate_ip_threat(ip)   #hàm ở trên
    ip_verdict = step1.get("verdict")
    result["step1_ip_status"] = ip_verdict

    # Nếu IP sạch → return luôn
    if ip_verdict == "FALSE_POSITIVE":
        result["verdict"] = "FALSE_POSITIVE"
        return result

    # ======================================================
    #                  BƯỚC 2 – Xác định chiều kết nối
    # ======================================================
    if agent_id:
        query = f'"{ip}" AND agent.id:"{agent_id}"'
    else:
        query = f'"{ip}"'
    # print("QUERY:", query)
    conn_logs = search_alerts(query)
    with open("connection_logs.json", "w") as f:
        json.dump(conn_logs, f, indent=4)
    log = conn_logs[0] if conn_logs else {}
    src_port = log.get("data", {}).get("win", {}).get("eventdata", {}).get("sourcePort", 0)
    dst_port = log.get("data", {}).get("win", {}).get("eventdata", {}).get("destinationPort", 0)
    
    device_ip = log.get("data", {}).get("win", {}).get("eventdata", {}).get("sourceIp", "")

    if int(src_port) > int(dst_port):
        direction = "OUTBOUND"
    else:
        direction = "INBOUND"

    result["step2_connection_direction"] = [src_port, dst_port, direction]

    # ======================================================
    #                  BƯỚC 3 – Kiểm tra tiến trình
    # ======================================================
    list_process_info = []
    list_process_mal = []
    tag_mal = 0
    if not conn_logs:
        result["step3_process_list"].append("Không lấy được tiến trình nào trên endpoint")
    else:
        for log_i in conn_logs:
            proc = log_i.get("data", {}).get("win", {}).get("eventdata", {})
            process_info = {
                "image": proc.get("image", None),
                "commandLine": proc.get("commandLine", None),
                "hash": proc.get("hashes", None),
                "user": proc.get("user", None),
                "parentCommandLine": proc.get("parentCommandLine", None),
                "parentImage": proc.get("parentImage", None),
                "parentUser": proc.get("parentUser", None),
            }
            tag = check_process_malicious(process_info.get("commandLine"), process_info.get("image"))
            if tag == True:
                tag_mal += 1
                list_process_mal.append(process_info)
            list_process_info.append(process_info)

        result["step3_process_list"] = list_process_info
        result["step3_process_mal"] = list_process_mal
        if tag_mal > 0:
            proc_status = "Phát hiện tiến trình đáng ngờ trên endpoint"
            
        else:
            proc_status = "Không phát hiện tiến trình đáng ngờ trên endpoint"

        result["step3_process_analysis"] = proc_status
    # ======================================================
    #                  BƯỚC 4 – Thông tin thiết bị
    # ======================================================
    if device_ip:
        device_info = get_agent_syscollector(agent_id)
        result["device_info"] = device_info
    else:
        result["device_info"] = "Không có agent_id, không lấy được thông tin thiết bị"
    # ======================================================
    #                  BƯỚC 5 – Kiểm tra tần suất
    # ======================================================
    freq_logs = search_alerts(f'{ip}', size=500)
    device_set = {l.get("agent", {}).get("id") for l in freq_logs}
    query_count = len(freq_logs)
    if len(device_set) > 10 and query_count > 300:
        freq_status = "Nhiều thiết truy cập → Hành vi nghiệp vụ"
    elif len(device_set) == 1 and query_count > 15 and "firewall" in result["device_info"]:
        freq_status = "Chỉ một thiết bị truy cập nhiều lần và là firewall → Hành vi nghiệp vụ của firewall"
    elif len(device_set) == 1 and query_count > 15:
        freq_status = "Chỉ một thiết bị truy cập nhiều lần → đáng ngờ --> Nghi nhiễm malware"
    else:
        freq_status = "Không đủ dữ liệu tần suất"

    result["step4_frequency_analysis"] = freq_status


    # ======================================================
    #                  BƯỚC 6 – KẾT LUẬN
    # ======================================================
    reason = None
    verdict = None   # This will be FP or TP

    ip_is_clean = (ip_verdict == "FP")
    has_mal_process = (tag_mal > 0)
    is_business_behavior = ("nghiệp vụ" in freq_status)

    # ====== TRƯỜNG HỢP FALSE POSITIVE ======
    if (ip_is_clean and not has_mal_process):
        reason = "IP sạch và không có tiến trình độc → FP"
        verdict = "FP"

    elif (not ip_is_clean and not has_mal_process):
        reason = "IP độc/đáng ngờ nhưng không có tiến trình độc → FP"
        verdict = "FP"

    elif (ip_verdict == "SUSPICIOUS" and is_business_behavior):
        reason = "IP đáng ngờ nhưng hành vi tần suất cho thấy là nghiệp vụ → FP"
        verdict = "FP"

    # ====== TRUE POSITIVE ======
    else:
        # còn lại => có dấu hiệu thật sự bất thường
        if ip_verdict == "MALICIOUS" and has_mal_process:
            reason = "IP độc và phát hiện tiến trình độc → TRUE POSITIVE"
        elif ip_verdict == "MALICIOUS":
            reason = "IP độc và hành vi kết nối bất thường → TRUE POSITIVE"
        elif has_mal_process:
            reason = "Tiến trình đáng ngờ kết nối IP không bình thường → TRUE POSITIVE"
        else:
            reason = "Hành vi kết nối bất thường → TRUE POSITIVE"
        verdict = "TP"

    result["reason"] = reason
    result["verdict"] = verdict

    return result


# a = evaluate_ip_connection_playbook("52.123.129.14","001")
# for key, value in a.items():
#     print(f"{key}: {value}")


# ======================================================
# PLAYBOOK FUNCTIONS - CONNECT MALICIOUS DOMAIN   
# ======================================================
# def evaluate_domain_connection_playbook(domain: str, agent_id: str):
#     """
#     Đánh giá connect domain theo 4 bước SOC:
#     B1: Đánh giá domain độc thật hay không (VirusTotal + heuristics)
#     B2: LẤY TẤT CẢ TIẾN TRÌNH truy vấn domain --> đánh giá từng tiến trình
#     B3: TẦN SUẤT truy vấn domain trên toàn hệ thống
#     B4: Tổng hợp để ra verdict chung
#     """

#     result = {
#         "domain": domain,
#         "step1_domain_status": None,
#         "step2_process_list": [],
#         "step2_process_mal": [],
#         "step2_process_status": None,
#         "step3_log_status": None,
#         "reason": None,
#         "verdict": None
#     }

#     # ============================================
#     # BƯỚC 1 – VirusTotal
#     # ============================================
#     vt = evaluate_domain_playbook(domain)

#     if "error" in vt:
#         result["step1_domain_status"] = f"Lỗi VT: {vt['error']}"
#         result["verdict"] = "ESCALATE"
#         result["reason"] = "Không đánh giá được VT → Escalate"
#         return result

#     domain_is_malicious = vt["verdict"] == "MALICIOUS"
#     result["step1_domain_status"] = (
#         "Domain bị VT đánh dấu độc" if domain_is_malicious 
#         else "Domain không bị VT đánh dấu độc"
#     )
    
#     # ============================================
#     # BƯỚC 2 – LẤY TẤT CẢ TIẾN TRÌNH TRUY VẤN DOMAIN
#     # ============================================
#     query = f'*{domain}* AND agent.id:{agent_id}'
#     logs = search_alerts(query, size=200)

#     list_process_info = []
#     list_process_mal = []
#     tag_mal = 0
#     if not logs:
#         result["step2_process_status"].append("Không lấy được tiến trình nào trên endpoint")
#     else:
#         for log in logs:
#             proc = log.get("data", {}).get("win", {}).get("eventdata", {})

#             process_info = {
#                 "originalFileName": proc.get("originalFileName"),
#                 "image": proc.get("image"),
#                 "commandLine": proc.get("commandLine"),
#                 "hash": proc.get("hashes"),
#                 "user": proc.get("user"),
#                 "parentCommandLine": proc.get("parentCommandLine"),
#                 "parentImage": proc.get("parentImage"),
#                 "parentUser": proc.get("parentUser"),
#             }
#             tag1 = check_process_malicious(process_info.get("commandLine"), process_info.get("image"))
#             tag2 = check_process_malicious(process_info.get("parentCommandLine"), process_info.get("parentImage"))
#             if tag1 or tag2:
#                 tag_mal += 1
#                 list_process_mal.append(process_info)
#             list_process_info.append(process_info)
#         result["step2_process_list"] = list_process_info
#         result["step2_process_mal"] = list_process_mal

#         if tag_mal > 0:
#             proc_status = "Phát hiện tiến trình đáng ngờ trên endpoint"
            
#         else:
#             proc_status = "Không phát hiện tiến trình đáng ngờ trên endpoint"

#         result["step3_process_analysis"] = proc_status

#     # ============================================
#     # BƯỚC 3 – TẦN SUẤT
#     # ============================================
#     # query_check = f'*{domain}*'
#     # print("QUERY FREQ:", query_check)
#     freq_logs = search_alerts(f'*{domain}*', size=500)
#     device_set = {l.get("agent", {}).get("id") for l in freq_logs}
#     query_count = len(freq_logs)

#     if len(device_set) > 10:
#         result["step3_log_status"] = "Tần suất cao → nghiệp vụ"
#         freq_flag = "FP_MASS"
#     elif len(device_set) == 1 and query_count > 20:
#         result["step3_log_status"] = "1 máy query nhiều lần → nghi nhiễm"
#         freq_flag = "SINGLE_INFECTED"
#     elif len(device_set) == 1 and 3 <= query_count <= 5:
#         result["step3_log_status"] = "1 máy query 3–5 lần → JS embedded"
#         freq_flag = "JS_EMBED"
#     else:
#         result["step3_log_status"] = "Không bất thường"
#         freq_flag = "NORMAL"

#     # ============================================
#     # BƯỚC 4 – TỔNG HỢP QUYẾT ĐỊNH
#     # ============================================

#     # CASE A: DOMAIN SẠCH
#     if not domain_is_malicious:
#         result["verdict"] = "FALSE_POSITIVE"

#         if freq_flag == "FP_MASS":
#             result["decision"] = "Domain sạch → nghiệp vụ"
#         elif "BROWSER_QUERY_CLEAN" in process_tags:
#             result["decision"] = "Domain sạch → browser query → JS/ads"
#         else:
#             result["decision"] = "Domain sạch → False Positive"

#         return result

#     # CASE B: DOMAIN ĐỘC
#     if domain_is_malicious:

#         if "NON_BROWSER_MALICIOUS_PROCESS" in process_tags:
#             result["verdict"] = "MALICIOUS"
#             result["decision"] = "Domain độc → tiến trình không phải browser → nghi mã độc"
#             return result

#         if "BROWSER_QUERY_MALICIOUS" in process_tags:
#             result["verdict"] = "MALICIOUS"
#             result["decision"] = "Domain độc → query bởi browser → nghi JS/extension/phishing"
#             return result

#         if "NO_PROCESS" in process_tags:
#             result["verdict"] = "ESCALATE"
#             result["decision"] = "Domain độc nhưng không lấy được tiến trình"
#             return result

#     # FALLBACK
#     result["verdict"] = "ESCALATE"
#     result["decision"] = "Không phân loại được → Escalate"
#     return result
@mcp.tool
def evaluate_domain_connection_playbook(domain: str, agent_id: str) -> dict:

    result = {
        "domain": domain,
        "step1_domain_status": None,
        "step2_process_list": [],
        "step2_process_mal": [],
        "step2_process_status": None,
        "step3_log_status": None,
        "reason": None,
        "verdict": None
    }

    # ============================================
    # STEP 1 – VirusTotal
    # ============================================
    vt = evaluate_domain_playbook(domain)

    if "error" in vt:
        result["step1_domain_status"] = f"Lỗi VT: {vt['error']}"
        result["verdict"] = "ESCALATE"
        result["reason"] = "Không đánh giá được VT"
        return result

    domain_is_malicious = vt["verdict"] == "MALICIOUS"
    domain_is_clean = not domain_is_malicious

    result["step1_domain_status"] = (
        "Domain bị VT đánh dấu độc" if domain_is_malicious else "Domain không bị VT đánh dấu độc"
    )
    
    # ============================================
    # STEP 2 – LẤY TẤT CẢ TIẾN TRÌNH
    # ============================================
    query = f'*{domain}* AND agent.id:{agent_id}'
    logs = search_alerts(query, size=200)

    list_process_info = []
    list_process_mal = []
    tag_mal = 0

    if not logs:
        result["step2_process_status"] = "Không lấy được tiến trình"
    else:
        for log in logs:
            proc = log.get("data", {}).get("win", {}).get("eventdata", {})
            process_info = {
                "originalFileName": proc.get("originalFileName"),
                "image": proc.get("image"),
                "commandLine": proc.get("commandLine"),
                "hash": proc.get("hashes"),
                "user": proc.get("user"),
                "parentCommandLine": proc.get("parentCommandLine"),
                "parentImage": proc.get("parentImage"),
                "parentUser": proc.get("parentUser"),
            }
            
            # Kiểm tra dấu hiệu tiến trình độc
            hash_mal = False
            hash_sha1 = r"SHA1=([A-Fa-f0-9]{40})"
            check_hash = check_file_vt_info(hash_sha1)
            if check_hash.get("malicious", 0) > 3:
                hash_mal = True
            is_mal = (
                check_process_malicious(process_info.get("commandLine"), process_info.get("image")) or
                check_process_malicious(process_info.get("parentCommandLine"), process_info.get("parentImage")) or 
                hash_mal
            )

            if is_mal:
                tag_mal += 1
                list_process_mal.append(process_info)

            list_process_info.append(process_info)

        result["step2_process_list"] = list_process_info
        result["step2_process_mal"] = list_process_mal
        result["step2_process_status"] = (
            "Có tiến trình đáng ngờ" if tag_mal > 0 else "Không phát hiện tiến trình đáng ngờ"
        )

    # ============================================
    # STEP 3 – TẦN SUẤT
    # ============================================
    freq_logs = search_alerts(f'*{domain}*', size=500)
    device_set = {l.get("agent", {}).get("id") for l in freq_logs}
    query_count = len(freq_logs)

    if len(device_set) > 10:
        result["step3_log_status"] = "Tần suất rất cao → nghiệp vụ"
        freq_flag = "FP_MASS"
    elif len(device_set) == 1 and query_count > 20:
        result["step3_log_status"] = "1 máy query nhiều → nghi nhiễm"
        freq_flag = "SINGLE_INFECTED"
    elif len(device_set) == 1 and 3 <= query_count <= 5:
        result["step3_log_status"] = "1 máy query 3–5 lần → JS embedded"
        freq_flag = "JS_EMBED"
    else:
        result["step3_log_status"] = "Không bất thường"
        freq_flag = "NORMAL"


    # ============================================
    # STEP 4 – QUYẾT ĐỊNH
    # (Theo yêu cầu bạn)
    # ============================================

    # 1️⃣ Domain sạch + không có tiến trình độc
    if domain_is_clean and tag_mal == 0:
        result["verdict"] = "FP"
        result["reason"] = "Domain sạch + tiến trình bình thường"
        return result

    # 2️⃣ Domain đáng ngờ nhưng không độc (heuristic) + tag_mal = 0
    if not domain_is_malicious and tag_mal == 0:
        result["verdict"] = "FP"
        result["reason"] = "Domain đáng ngờ nhưng tiến trình bình thường"
        return result

    # 3️⃣ Domain đáng ngờ + tag_mal = 0 + hành vi nghiệp vụ (FP_MASS)
    if domain_is_malicious and tag_mal == 0 and freq_flag == "FP_MASS":
        result["verdict"] = "FP"
        result["reason"] = "Domain đáng ngờ nhưng lưu lượng hàng loạt → nghiệp vụ"
        return result

    # 4️⃣ Còn lại → TRUE_POSITIVE
    result["verdict"] = "TP"
    result["reason"] = "Có dấu hiệu mã độc (domain hoặc tiến trình)"
    return result

# res = evaluate_domain_connection_playbook("facebook.com", agent_id="001")
# json_output = json.dumps(res, ensure_ascii=False, indent=4)
# print(json_output)


# ============================================
# PLAYBOOK FUNCTIONS - FILE BÂT THƯỜNG
# ============================================
@mcp.tool
def file_malcious_playbook(file_hash: str, path: str) -> dict:
    """ 
    Thực hiện playbook kiểm tra file bất thường:    
        1. Kiểm tra VirusTotal
        2. Kiểm tra đường dẫn file nhạy cảm
        3. Kiểm tra tên file đáng ngờ
        4. Kiểm tra user tạo file
        5. Tổng hợp kết luận

    Args:
        file_hash: hash file cần kiểm tra
    """
    vt = check_file_playbook(file_hash, path)
    check_path = is_suspicious_executable(path)
    check_name = check_filename_reputation(path)
    check_user = check_file_creator_user(path)
    summary = summarize_playbook(vt)
    result = {
        "virus_total": vt,
        "suspicious_path": check_path,
        "suspicious_name": check_name,
        "creator_user": check_user,
        "summary": summary
    }
    return result

@mcp.tool
def process_malicious_check(commandline=None, path=None, hash=None, parent_commandline=None, parent_path=None):
    """
    Đánh giá tiến trình có đáng ngờ hay không dựa trên:
        - commandline
        - đường dẫn file
        - hash file
        - commandline tiến trình cha
        - đường dẫn file tiến trình cha
        - user tạo tiến trình
    """
    result = {}
    
    # 1. Kiểm tra commandline
    commandline_check = check_process_malicious(commandline, path)
    result["commandline_check"] = commandline_check
    
    # 2. Kiểm tra đường dẫn file
    check_path = is_suspicious_executable(path) if path else {"is_suspicious": False, "reason": "No path provided"}
    result["path_check"] = check_path
    
    # 3. Kiểm tra hash file trên VirusTotal
    if hash:
        # Trích xuất SHA256 từ chuỗi hash nếu có nhiều hash
        if "SHA256=" in hash:
            import re
            sha256_match = re.search(r"SHA256=([A-Fa-f0-9]{64})", hash)
            hash_to_check = sha256_match.group(1) if sha256_match else hash
        else:
            hash_to_check = hash
        
        hash_check = check_file_vt_info(hash_to_check)
        result["hash_check"] = hash_check
    else:
        result["hash_check"] = {"crit1": "No hash provided"}
    
    # 4. Kiểm tra parent commandline
    parent_commandline_check = check_process_malicious(parent_commandline, parent_path)
    result["parent_commandline_check"] = parent_commandline_check
    
    # 5. Kiểm tra parent path
    check_parent_path = is_suspicious_executable(parent_path) if parent_path else {"is_suspicious": False, "reason": "No parent path provided"}
    result["parent_path_check"] = check_parent_path
    
    # 6. Kiểm tra user tạo tiến trình
    if path:
        filename = path.split("\\")[-1]  # Lấy tên file từ đường dẫn
        user_info = check_file_creator_user(filename)
        result["user_create_check"] = user_info
        
    else:
        result["user_create_check"] = {"note": "Không có path để kiểm tra user"}
    
    # 7. Tổng hợp đánh giá
    is_malicious = False
    reasons = []
    
    if commandline_check:
        is_malicious = True
        reasons.append("Commandline chứa pattern đáng ngờ")
    
    if check_path.get("is_suspicious"):
        is_malicious = True
        reasons.append("File nằm ở vị trí nhạy cảm")
    
    if hash_check.get("malicious", 0) >= 3:
        is_malicious = True
        reasons.append(f"VirusTotal phát hiện {hash_check.get('malicious')} AV báo độc")
    
    if parent_commandline_check:
        is_malicious = True
        reasons.append("Parent process có commandline đáng ngờ")
    
    if check_parent_path.get("is_suspicious"):
        is_malicious = True
        reasons.append("Parent process nằm ở vị trí nhạy cảm")
    
    result["verdict"] = "MALICIOUS" if is_malicious else "CLEAN"
    result["reasons"] = reasons if reasons else ["Không phát hiện dấu hiệu đáng ngờ"]

    return result

#print(check_file_playbook("6d7f542ed46fcb02893a8672eb405d4b543e2a92db1ac22b5d53dbf303568b25", "C:/Users/admin/Downloads/mas_17-20230810T055912Z-001/mas_17-20230810T055912Z-001/mas_17/MAS_1.7_Password_1234/MAS_1.7/All-In-One-Version/MAS_AIO.cmd"))

if __name__ == "__main__":
    print(f"Starting Wazuh MCP server on {BASE_URL}...")
    print(f"VirusTotal API: {'Configured' if VIRUSTOTAL_API_KEY else 'Not configured'}")
    print(f"AbuseIPDB API: {'Configured' if ABUSEIPDB_API_KEY else 'Not configured'}")
    mcp.run()

