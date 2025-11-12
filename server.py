import os
import requests
import json
import re
import base64
from fastmcp import FastMCP
from requests.auth import HTTPBasicAuth

from dotenv import load_dotenv
import os

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
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(
            f"{VIRUSTOTAL_BASE_URL}/ip_addresses/{ip}",
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json().get("data", {})
            attributes = data.get("attributes", {})
            
            return {
                "ip": ip,
                "country": attributes.get("country"),
                "asn": attributes.get("asn"),
                "as_owner": attributes.get("as_owner"),
                "reputation": attributes.get("reputation"),
                "last_analysis_stats": attributes.get("last_analysis_stats"),
                "malicious": attributes.get("last_analysis_stats", {}).get("malicious", 0),
                "suspicious": attributes.get("last_analysis_stats", {}).get("suspicious", 0),
                "harmless": attributes.get("last_analysis_stats", {}).get("harmless", 0),
                "undetected": attributes.get("last_analysis_stats", {}).get("undetected", 0),
                "verdict": "MALICIOUS" if attributes.get("last_analysis_stats", {}).get("malicious", 0) > 0 else "CLEAN"
            }
        elif response.status_code == 404:
            return {"ip": ip, "verdict": "NOT_FOUND", "message": "IP not found in VirusTotal database"}
        else:
            return {"error": f"VT API error {response.status_code}: {response.text}"}
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
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(
            f"{VIRUSTOTAL_BASE_URL}/domains/{domain}",
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json().get("data", {})
            attributes = data.get("attributes", {})
            
            return {
                "domain": domain,
                "reputation": attributes.get("reputation"),
                "categories": attributes.get("categories"),
                "last_analysis_stats": attributes.get("last_analysis_stats"),
                "malicious": attributes.get("last_analysis_stats", {}).get("malicious", 0),
                "suspicious": attributes.get("last_analysis_stats", {}).get("suspicious", 0),
                "harmless": attributes.get("last_analysis_stats", {}).get("harmless", 0),
                "undetected": attributes.get("last_analysis_stats", {}).get("undetected", 0),
                "creation_date": attributes.get("creation_date"),
                "last_update_date": attributes.get("last_update_date"),
                "verdict": "MALICIOUS" if attributes.get("last_analysis_stats", {}).get("malicious", 0) > 0 else "CLEAN"
            }
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
            
            return {
                "hash": file_hash,
                "file_name": attributes.get("meaningful_name"),
                "file_type": attributes.get("type_description"),
                "size": attributes.get("size"),
                "last_analysis_stats": attributes.get("last_analysis_stats"),
                "malicious": attributes.get("last_analysis_stats", {}).get("malicious", 0),
                "suspicious": attributes.get("last_analysis_stats", {}).get("suspicious", 0),
                "harmless": attributes.get("last_analysis_stats", {}).get("harmless", 0),
                "undetected": attributes.get("last_analysis_stats", {}).get("undetected", 0),
                "reputation": attributes.get("reputation"),
                "first_submission_date": attributes.get("first_submission_date"),
                "last_submission_date": attributes.get("last_submission_date"),
                "verdict": "MALICIOUS" if attributes.get("last_analysis_stats", {}).get("malicious", 0) > 0 else "CLEAN"
            }
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

# ========== NEW: ABUSEIPDB TOOL ==========

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
            
            abuse_score = data.get("abuseConfidenceScore", 0)
            verdict = "CLEAN"
            if abuse_score > 75:
                verdict = "MALICIOUS"
            elif abuse_score > 25:
                verdict = "SUSPICIOUS"
            
            return {
                "ip": ip,
                "abuse_confidence_score": abuse_score,
                "country": data.get("countryCode"),
                "usage_type": data.get("usageType"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "is_whitelisted": data.get("isWhitelisted"),
                "total_reports": data.get("totalReports"),
                "num_distinct_users": data.get("numDistinctUsers"),
                "last_reported_at": data.get("lastReportedAt"),
                "verdict": verdict
            }
        else:
            return {"error": f"AbuseIPDB API error {response.status_code}: {response.text}"}
    except Exception as e:
        return {"error": str(e)}

# ========== NEW: BULK IOC CHECKER ==========

@mcp.tool()
def check_alert_iocs(alert_json: str):
    """Extract and check all IOCs (IPs, domains, hashes) from Wazuh alert data.
    
    Args:
        alert_json: JSON string of alert data from search_alerts
    
    Returns:
        Dict with checked IPs, domains, and hashes with their threat intel results
    """
    try:
        # Parse alert data
        if isinstance(alert_json, str):
            alert_data = json.loads(alert_json)
        else:
            alert_data = alert_json
        
        results = {
            "summary": {
                "total_ips_found": 0,
                "public_ips_checked": 0,
                "malicious_ips": 0,
                "suspicious_ips": 0
            },
            "ips_checked": []
        }
        
        # Convert alert data to string for regex extraction
        alert_str = json.dumps(alert_data)
        
        # Extract IPs using regex
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = set(re.findall(ip_pattern, alert_str))
        results["summary"]["total_ips_found"] = len(ips)
        
        # Filter out private IPs
        private_ip_patterns = [
            r'^10\.',
            r'^172\.(1[6-9]|2[0-9]|3[01])\.',
            r'^192\.168\.',
            r'^127\.',
            r'^0\.',
            r'^169\.254\.',
            r'^255\.'
        ]
        
        public_ips = []
        for ip in ips:
            is_private = any(re.match(pattern, ip) for pattern in private_ip_patterns)
            if not is_private and ip != "0.0.0.0":
                public_ips.append(ip)
        
        # Check public IPs (limit to 5 to avoid rate limits)
        for ip in list(public_ips)[:5]:
            vt_result = virustotal_check_ip(ip)
            abuse_result = abuseipdb_check_ip(ip)
            
            combined_verdict = "CLEAN"
            if vt_result.get("verdict") == "MALICIOUS" or abuse_result.get("verdict") == "MALICIOUS":
                combined_verdict = "MALICIOUS"
                results["summary"]["malicious_ips"] += 1
            elif vt_result.get("verdict") == "SUSPICIOUS" or abuse_result.get("verdict") == "SUSPICIOUS":
                combined_verdict = "SUSPICIOUS"
                results["summary"]["suspicious_ips"] += 1
            
            results["ips_checked"].append({
                "ip": ip,
                "verdict": combined_verdict,
                "virustotal": vt_result,
                "abuseipdb": abuse_result
            })
            results["summary"]["public_ips_checked"] += 1
        
        return results
    except Exception as e:
        return {"error": str(e)}
    
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


if __name__ == "__main__":
    print(f"Starting Wazuh MCP server on {BASE_URL}...")
    print(f"VirusTotal API: {'Configured' if VIRUSTOTAL_API_KEY else 'Not configured'}")
    print(f"AbuseIPDB API: {'Configured' if ABUSEIPDB_API_KEY else 'Not configured'}")
    mcp.run()


