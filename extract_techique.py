import json
with open("D:/DoAn/code/Wazuh-MCP-Server/alert.json", "r", encoding="utf-8") as f:
    data = json.load(f)
# print(type(data))
def extract_techniques(json_alert):
    techniques = json_alert.get("_source").get("rule").get("mitre").get("id")
    return techniques

techniques = extract_techniques(data)
print(techniques)