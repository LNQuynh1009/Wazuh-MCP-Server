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

#=========end functions===============

# if __name__ == "__main__":
#     with open("D:/DoAn/code/Wazuh-MCP-Server/alert.json", "r", encoding="utf-8") as f:
#         alert = json.load(f)    
#     # print(type(data))
#     repo = mitre_repository("D:\DoAn\code\Wazuh-MCP-Server\enterprise-attack.json")
#     techniques = extract_techniques(alert)
#     print(techniques)
#     for i in techniques:
#     # tid = "T1087.001"
#         t = repo.find_technique_by_external_id(i)
#         if t:
#             print("TECH:", t.name)
#             print("ID:", t.external_id)
#             print("Phase Attack:", t.phase[:5])
#             desc = get_full_description_from_url(t.url)
#             print("Description:", desc)
#             # print("Tactics:", [xx.name for xx in t.tactics])
#             print("Attacker groups have used this technique before:", [xx.name for xx in t.groups[:5]])
#             print("Malwares have used this technique before:", [xx.name for xx in t.malwares[:5]])
#             # print("Tools:", [xx.name for xx in t.tools])
#             print("Mitigations:", [xx.name for xx in t.mitigations[:5]])
#             print("Campaign haved used this technique before:", [xx.name for xx in t.campaigns[:5]])
#             print("URL of this technique:", t.url)
#             print("Tools that help attackers perform this technique :", [tool.external_id or tool.id for tool in t.tools[:5]])

#             # print("\n== DETAIL TOOLS ==")
#             # for tool in t.tools:
#             #     print("   -", tool.external_id, "|", tool.description)
#         else:
#             print("Technique not found")
#         print


# Load MITRE JSON
from mcp.types import TextContent

MITRE_PATH = os.getenv("MITRE_ATTACK_PATH", "D:/DoAn/code/Wazuh-MCP-Server/enterprise-attack.json")

def load_repo():
    return mitre_repository(MITRE_PATH)
   
# ===================  MCP SERVER  ========================================

# mcp = FastMCP("mitre_mcp_server")


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
    result = find_technique("T1087.001")
    print(result.text)






    