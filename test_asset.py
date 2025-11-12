import os
import requests
import urllib3
from dotenv import load_dotenv

# Tắt cảnh báo SSL tự ký
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# === Load environment ===
load_dotenv()

WAZUH_HOST = os.getenv("WAZUH_HOST", "https://192.168.17.132")
WAZUH_PORT = os.getenv("WAZUH_PORT", "55000")
WAZUH_USER = os.getenv("WAZUH_USER", "wazuh")
WAZUH_PASS = os.getenv("WAZUH_PASS", "wazuh")
ALLOW_SELF_SIGNED = os.getenv("WAZUH_ALLOW_SELF_SIGNED", "true").lower() == "true"
VERIFY_SSL = not ALLOW_SELF_SIGNED

BASE_URL = f"{WAZUH_HOST}:{WAZUH_PORT}"

# === Lấy token đăng nhập Wazuh ===
def get_wazuh_token():
    url = f"{BASE_URL}/security/user/authenticate"
    resp = requests.get(url, auth=(WAZUH_USER, WAZUH_PASS), verify=VERIFY_SSL)
    resp.raise_for_status()
    return resp.json()["data"]["token"]

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
def get_agent_syscollector(agent_id):
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


if __name__ == "__main__":
    agent_id = "001"  # 🔧 Thay bằng agent ID của bạn
    info = get_agent_syscollector(agent_id)

    print("\n=== Agent System Information ===")
    for section, data in info["syscollector"].items():
        print(f"\n--- {section.upper()} ---")
        print(data)
