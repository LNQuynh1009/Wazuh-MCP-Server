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

# === Load environment variables from file env===
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

# ========== EXISTING WAZUH TOOLS ==========

@mcp.tool()
def ping():
    """Test connection to Wazuh API."""
    try:
        token = get_wazuh_token()
        return {"status": "ok", "token_length": len(token)}
    except Exception as e:
        return {"status": "error", "detail": str(e)}

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
    return hits

# ========== NEW: VIRUSTOTAL TOOLS ==========

@mcp.tool()
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

@mcp.tool()
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

@mcp.tool()
def check_ip2location(ip: str):
    """Check IP geolocation using ip2location 
    Args:
        ip: IP address to check (e.g., '
    """
    try:
        print(IP2LOCATION_API_KEY)
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

@mcp.tool()
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
            return attributes

        elif response.status_code == 404:
            return {"domain": domain, "verdict": "NOT_FOUND", "message": "Domain not found in VirusTotal database"}
        else:
            return {"error": f"VT API error {response.status_code}: {response.text}"}
    except Exception as e:
        return {"error": str(e)}

@mcp.tool()
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

@mcp.tool()
def virustotal_check_url(url: str):
    """Check a URL reputation on VirusTotal.
    
    Args:
        url: URL to check (e.g., 'https://example.com')
    
    Returns:
        Dict with URL reputation, malicious detections, categories, etc.
    """
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VIRUSTOTAL_API_KEY not set in environment"}
    
    try:
        # VirusTotal uses base64 URL-safe encoding for URL identifiers
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(
            f"{VIRUSTOTAL_BASE_URL}/urls/{url_id}",
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json().get("data", {})
            attributes = data.get("attributes", {})
            
            return {
                "url": url,
                "reputation": attributes.get("reputation"),
                "last_analysis_stats": attributes.get("last_analysis_stats"),
                "malicious": attributes.get("last_analysis_stats", {}).get("malicious", 0),
                "suspicious": attributes.get("last_analysis_stats", {}).get("suspicious", 0),
                "harmless": attributes.get("last_analysis_stats", {}).get("harmless", 0),
                "undetected": attributes.get("last_analysis_stats", {}).get("undetected", 0),
                "categories": attributes.get("categories"),
                "last_submission_date": attributes.get("last_submission_date"),
                "verdict": "MALICIOUS" if attributes.get("last_analysis_stats", {}).get("malicious", 0) > 0 else "CLEAN"
            }
        elif response.status_code == 404:
            return {"url": url, "verdict": "NOT_FOUND", "message": "URL not found in VirusTotal database"}
        else:
            return {"error": f"VT API error {response.status_code}: {response.text}"}
    except Exception as e:
        return {"error": str(e)}

# ========== NEW: BULK IOC CHECKER ==========

# @mcp.tool()
# def check_alert_iocs(alert_json: str):
#     """Extract and check all IOCs (IPs, domains, hashes) from Wazuh alert data.
    
#     Args:
#         alert_json: JSON string of alert data from search_alerts
    
#     Returns:
#         Dict with checked IPs, domains, and hashes with their threat intel results
#     """
#     try:
#         # Parse alert data
#         if isinstance(alert_json, str):
#             alert_data = json.loads(alert_json)
#         else:
#             alert_data = alert_json
        
#         results = {
#             "summary": {
#                 "total_ips_found": 0,
#                 "public_ips_checked": 0,
#                 "malicious_ips": 0,
#                 "suspicious_ips": 0
#             },
#             "ips_checked": []
#         }
        
#         # Convert alert data to string for regex extraction
#         alert_str = json.dumps(alert_data)
        
#         # Extract IPs using regex
#         ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
#         ips = set(re.findall(ip_pattern, alert_str))
#         results["summary"]["total_ips_found"] = len(ips)
        
#         # Filter out private IPs
#         private_ip_patterns = [
#             r'^10\.',
#             r'^172\.(1[6-9]|2[0-9]|3[01])\.',
#             r'^192\.168\.',
#             r'^127\.',
#             r'^0\.',
#             r'^169\.254\.',
#             r'^255\.'
#         ]
        
#         public_ips = []
#         for ip in ips:
#             is_private = any(re.match(pattern, ip) for pattern in private_ip_patterns)
#             if not is_private and ip != "0.0.0.0":
#                 public_ips.append(ip)
        
#         # Check public IPs (limit to 5 to avoid rate limits)
#         for ip in list(public_ips)[:5]:
#             vt_result = virustotal_check_ip(ip)
#             abuse_result = abuseipdb_check_ip(ip)
            
#             combined_verdict = "CLEAN"
#             if vt_result.get("verdict") == "MALICIOUS" or abuse_result.get("verdict") == "MALICIOUS":
#                 combined_verdict = "MALICIOUS"
#                 results["summary"]["malicious_ips"] += 1
#             elif vt_result.get("verdict") == "SUSPICIOUS" or abuse_result.get("verdict") == "SUSPICIOUS":
#                 combined_verdict = "SUSPICIOUS"
#                 results["summary"]["suspicious_ips"] += 1
            
#             results["ips_checked"].append({
#                 "ip": ip,
#                 "verdict": combined_verdict,
#                 "virustotal": vt_result,
#                 "abuseipdb": abuse_result
#             })
#             results["summary"]["public_ips_checked"] += 1
        
#         return results
#     except Exception as e:
#         return {"error": str(e)}
    
#Lấy thông tin về hardware, processes, os, package, network treena agent
# === Hàm gọi API Wazuh ===
def wazuh_get(path, params=None):
    token = get_wazuh_token()
    headers = {"Authorization": f"Bearer {token}"}
    url = f"{BASE_URL}{path}"
    print(f"DEBUG URL: {url}")
    resp = requests.get(url, headers=headers, params=params, verify=VERIFY_SSL)
    resp.raise_for_status()
    return resp.json()

# === Lấy toàn bộ thông tin hệ thống của agent ===
@mcp.tool()
def get_agent_syscollector(agent_id):
    """
    Lấy toàn bộ thông tin hệ thống của một agent thông qua API syscollector của Wazuh.

    Thông tin được thu thập bao gồm:
      - os: Thông tin hệ điều hành (Windows, Linux,...)
      - netiface: Thông tin các card mạng (network interfaces)
      - netport: Các cổng mạng đang mở trên agent
      - netproto: Các giao thức mạng đang sử dụng
      - packages: Các gói phần mềm đã cài đặt
      - processes: Các tiến trình đang chạy
      - ports: Các cổng liên quan (mở/tồn tại)
      - hardware: Thông tin phần cứng của agent
      - hotfixes: Các bản vá bảo mật đã cài đặt trên hệ thống

    Tham số:
        agent_id (str): ID của agent cần lấy thông tin.

    Trả về:
        dict: Kết quả dưới dạng dictionary gồm agent_id và dữ liệu syscollector của từng module.
              Nếu có lỗi khi gọi API từng module, trả về lỗi và mã trạng thái HTTP tương ứng.

    Ví dụ:
        get_agent_syscollector("001")

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

#=========Mapping mitre technique============= 
import json
import os
from urllib.request import urlopen
from bs4 import BeautifulSoup

#=========classes=============
class technique:   #attack-pattern
    def __init__(self, id, name, description=None, url=None):
        self.id = id #đây không phải id của technique mà là stix id
        self.external_id = None  # Txxxx, đây là id của technique
        self.name = name
        self.description = description
        self.url = url
        self.phase = []  # kill_chain_phases
        self.detection = []
        self.platforms = []
        self.data_sources = []
        self.mitigations = []  # list of mitigation ids
        self.groups = []       # list of group ids
        self.malwares = []     # list of malware ids
        self.tools = []        # list of tool ids
        self.campaigns = []  # list of campaign ids

class group_attacker:  #intrusion-set
    def __init__(self, id, name, description=None, url=None):
        self.id = id
        self.name = name
        self.description = description
        self.url = url
        self.external_id = None #Gxxxx
        self.techniques = []

class malware:   #malware
    def __init__(self, id, name, description=None, url=None):
        self.id = id
        self.name = name
        self.description = description
        self.url = url
        self.external_id = None #Sxxxx
        self.techniques = []

class tool:   #tool
    def __init__(self, id, description=None, url=None):
        self.id = id
        self.description = description
        self.url = url
        self.external_id = None #Sxxxx
        self.techniques = []

class campaign:  #campaign
    def __init__(self, id, name, description=None, url=None):
        self.id = id
        self.name = name
        self.description = description
        self.url = url
        self.external_id = None  # Cxxxx
        self.first_seen = None
        self.last_seen = None
        self.techniques = []

class mitigation:  #course-of-action
    def __init__(self, id, name, description=None, url=None):
        self.id = id
        self.name = name
        self.description = description
        self.url = url
        self.techniques = []  # techniques mitigated by this action


class mitre_repository:
    def __init__(self, json_path):
        self.techniques = {}
        self.groups = {}        
        self.malwares = {}
        self.tools = {}
        self.mitigations = {}
        self.external_id_map = {}  # T1078 → stix-id
        self.relationships = []  # list of relationships
        self.campaigns = {}

        self.load(json_path)
        self.resolve_relationships()

    def load(self, path):
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        list_objs = data.get("objects", [])
        for obj in list_objs:
            t = obj.get("type")

            # TECHNIQUE (Txxxx)
            if t == "attack-pattern":
                o = technique(obj["id"], obj["name"], obj.get("description"))

                # external_id (Txxxx)
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        o.external_id = ref.get("external_id")
                        o.url = ref.get("url")
                        break
                if obj.get("kill_chain_phases"):
                    for kill in obj.get("kill_chain_phases", []):
                        phase = kill.get("phase_name")
                        o.phase.append(phase)

                if obj.get("x_mitre_detection"):
                    detection = obj.get("x_mitre_detection")
                    o.detection.append(detection)

                if obj.get("x_mitre_platforms"):
                    platforms = obj.get("x_mitre_platforms")
                    o.platforms.extend(platforms)
                
                if obj.get("x_mitre_data_sources"):
                    data_sources = obj.get("x_mitre_data_sources")
                    o.data_sources.extend(data_sources)
                self.techniques[obj["id"]] = o
                self.external_id_map[o.external_id] = obj["id"]

            # GROUP
            elif t == "intrusion-set":
                o = group_attacker(obj["id"], obj["name"], obj.get("description"))
                # external_id (Txxxx)
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        o.external_id = ref.get("external_id")
                        o.url = ref.get("url")
                        break
                self.groups[obj["id"]] = o

            # TOOL
            elif t == "tool":
                o = tool(obj["id"], obj.get("description"))
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        o.external_id = ref.get("external_id")
                        o.url = ref.get("url")
                        break
                self.tools[obj["id"]] = o

            # MALWARE
            elif t == "malware":
                o = malware(obj["id"], obj["name"], obj.get("description"))
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        o.external_id = ref.get("external_id")
                        o.url = ref.get("url")
                        break
                self.malwares[obj["id"]] = o

            # MITIGATION
            elif t == "course-of-action":
                o = mitigation(obj["id"], obj["name"], obj.get("description"))
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        o.external_id = ref.get("external_id")
                        o.url = ref.get("url")
                        break
                self.mitigations[obj["id"]] = o
            
            elif t == "campaign":
                o = campaign(obj["id"], obj["name"], obj.get("description"))
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        o.external_id = ref.get("external_id")
                        o.url = ref.get("url")
                        break
                o.first_seen = obj.get("first_seen")
                o.last_seen = obj.get("last_seen")
                self.campaigns[obj["id"]] = o
            
            elif t == "relationship":
                self.relationships.append(obj)
        self.resolve_relationships()

    def resolve_relationships(self):
        for rel in self.relationships:
            src = rel.get("source_ref")
            tgt = rel.get("target_ref")
            t = rel.get("relationship_type")

            # technique mitigated by course-of-action
            if t == "mitigates":
                if src in self.mitigations and tgt in self.techniques:
                    self.mitigations[src].techniques.append(self.techniques[tgt])
                    self.techniques[tgt].mitigations.append(self.mitigations[src])
            # technique used by group
            elif t == "uses":
                if src in self.groups and tgt in self.techniques:
                    self.groups[src].techniques.append(self.techniques[tgt])
                    self.techniques[tgt].groups.append(self.groups[src])
                if src in self.malwares and tgt in self.techniques:
                    self.malwares[src].techniques.append(self.techniques[tgt])
                    self.techniques[tgt].malwares.append(self.malwares[src])
                if src in self.tools and tgt in self.techniques:
                    self.tools[src].techniques.append(self.techniques[tgt])
                    self.techniques[tgt].tools.append(self.tools[src])
                if src in self.campaigns and tgt in self.techniques:
                    self.campaigns[src].techniques.append(self.techniques[tgt])
                    self.techniques[tgt].campaigns.append(self.campaigns[src])

    def find_technique_by_external_id(self, external_id) -> technique | None:
        stix_id = self.external_id_map.get(external_id)
        if stix_id:
            return self.techniques.get(stix_id)
        return None
#=========end classes=============

#=========functions===============
def extract_techniques(json_alert):
    techniques = json_alert.get("_source").get("rule").get("mitre").get("id")
    return techniques

def get_full_description_from_url(url: str) -> str:
    try:
        html = urlopen(url).read()
        soup = BeautifulSoup(html, "html.parser")

        # phần mô tả luôn nằm trong <div class="description-body">
        desc = soup.find("div", {"class": "description-body"})
        if desc:
            return desc.get_text(strip=True)
        return "No description found!"
    except Exception as e:
        return f"Error: {e}"

# Load MITRE JSON
from mcp.types import TextContent
MITRE_PATH = os.getenv("MITRE_ATTACK_PATH", "D:/DoAn/code/Wazuh-MCP-Server/enterprise-attack.json")
def load_repo():
    return mitre_repository(MITRE_PATH)

#=========end functions===============

# ===================  MCP SERVER  ========================================
@mcp.tool() #tool này không cần nhưng bỏ thì tiếc :)))
def extract_techniques(json_alert):
    """"
    extract techniques from wazuh alert json
    Args:
        json_alert: json alert from wazuh
    Returns:
        List of techniques
    """
    techniques = json_alert.get("_source").get("rule").get("mitre").get("id")
    return techniques

@mcp.tool()
def find_technique(tech_id: str):
    """
    Query MITRE technique information by external_id (e.g. T1087.001)
    Args:
        tech_id: external_id of technique (e.g. T1087.001)
    Returns:
        information about the technique
    """
    repo = load_repo()
    t = repo.find_technique_by_external_id(tech_id)

    if not t:
        return TextContent(type="text", text=f"Technique {tech_id} not found")
    desc = get_full_description_from_url(t.url)
    result = {
        "id": t.external_id,
        "name": t.name,
        "description": t.description,
        "url": t.url,
        "phase": t.phase,
        "groups": [[g.name, g.description] for g in t.groups[:5]],
        "malwares": [[m.name, m.description] for m in t.malwares[:5]],
        "tools": [[x.external_id, x.description] for x in t.tools[:5]],
        "mitigations": [[m.name, m.description] for m in t.mitigations[:5]],
        "campaigns": [[c.name, c.description] for c in t.campaigns[:5]],
        "detection": desc,
        "platforms": t.platforms,
        "data_sources": t.data_sources,
    }

    return TextContent(
        type="text",
        text=json.dumps(result, indent=2, ensure_ascii=False)
    )

#======= cHECK FILE ======================
@mcp.tool()
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
@mcp.tool()
def check_file_path(path):
    """
    Kiểm tra đường dẫn file xem có nằm trong thư mục nhạy cảm
    và có phần mở rộng thực thi nguy hiểm hay không.

    Args:
        path: đường dẫn file

    Returns:
        Dict với crit2: "OK" hoặc cảnh báo file thực thi trong thư mục nhạy cảm
    """
    path_lc = path.lower()

    dangerous_exts = [".exe", ".dll", ".bat", ".cmd", ".vbs", ".js", ".ps1", ".sh"]
    suspicious_dirs = [
        "c:/", "windows/system32", "windows/syswow64", "programdata",
        "program files", "appdata", "localappdata", "users/public", "temp"
    ]

    _, ext = os.path.splitext(path_lc)

    in_sensitive_dir = any(i in path_lc.replace("\\", "/") for i in suspicious_dirs)
    is_exec = ext in dangerous_exts

    if in_sensitive_dir and is_exec:
        return {"crit2": "File thực thi nằm trong thư mục nhạy cảm"}

    return {"crit2": "OK"}
@mcp.tool()
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
@mcp.tool()
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
@mcp.tool()
def check_file_creator_user(filename):
    """
    Xác định user tạo file từ Wazuh logs, đồng thời cảnh báo
    nếu file do user dịch vụ (nguy cơ exploit) tạo.

    Args:
        filename: tên file

    Returns:
        Dict với crit4: thông tin user tạo file hoặc cảnh báo
    """
    user_info = get_user_from_wazuh_logs(filename)

    user = user_info.get("user")

    if not user:
        return {"crit4": "Không xác định được user", "detail": user_info}

    # User dịch vụ → nguy cơ exploit
    suspicious_users = ["www-data", "apache", "nginx", "mysql", "system", "network service"]

    if str(user).lower() in suspicious_users:
        return {"crit4": "File do user dịch vụ tạo — có thể bị exploit", "detail": user_info}

    return {"crit4": f"User tạo file: {user}", "detail": user_info}

@mcp.tool()
def summarize_playbook(results):
    """
    Tổng hợp kết quả các tiêu chí kiểm tra file và đưa ra kết luận cuối.

    Args:
        results: dict chứa kết quả crit1 -> crit4

    Returns:
        Chuỗi kết luận (ví dụ: "CHẮC CHẮN LÀ MÃ ĐỘC", "NGHI NGỜ MẠNH", ...)
    """
    malicious = results["crit1"].get("malicious", 0)

    # Quy tắc đánh giá cuối
    if malicious >= 25:
        return "=> KẾT LUẬN: CHẮC CHẮN LÀ MÃ ĐỘC"

    if 5 <= malicious < 25:
        return "=> KẾT LUẬN: NGHI NGỜ MẠNH (Có thể là crack/hacktool)"

    if results["crit2"] != "OK":
        return "=> KẾT LUẬN: File thực thi trong thư mục nhạy cảm → nguy cơ cao"

    if "đáng ngờ" in results["crit3"].lower():
        return "=> KẾT LUẬN: Tên file nguy hiểm → cần phân tích thêm"

    if "exploit" in results["crit4"].lower():
        return "=> KẾT LUẬN: File được tạo bởi user dịch vụ → nguy cơ bị tấn công"

    return "=> KẾT LUẬN: KHÔNG ĐỦ DỮ LIỆU, ĐỀ XUẤT TẢI FILE VỀ PHÂN TÍCH"

@mcp.tool()
def check_file_playbook(file_hash, path):
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
    r2 = check_file_path(path)
    result["crit2"] = r2["crit2"]

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

    return result

#============= CHECK FILE END ==================

#============= CHECK DOMAIN ==============
@mcp.tool()
def evaluate_domain_playbook(domain: str):
    """
    Đánh giá độ nguy hiểm của một domain dựa trên các tiêu chí:
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
#============= CHECK DOMAIN END ==============

#============= CHECK IP ==============
@mcp.tool()
def check_ip_vpn(ip: str):
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

@mcp.tool()
def evaluate_ip_threat(ip: str):
    """
    Đánh giá IP theo playbook, chỉ trả về kết quả các tiêu chí (không chứa raw data).
    Args:
        ip: Địa chỉ IP cần đánh giá
    """

    result = {
        "ip": ip,
        "criteria": {
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


if __name__ == "__main__":
    print(f"Starting Wazuh MCP server on {BASE_URL}...")
    print(f"VirusTotal API: {'Configured' if VIRUSTOTAL_API_KEY else 'Not configured'}")
    print(f"AbuseIPDB API: {'Configured' if ABUSEIPDB_API_KEY else 'Not configured'}")
    mcp.run()


