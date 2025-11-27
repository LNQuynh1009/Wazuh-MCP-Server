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
    user_info = get_user_from_wazuh_logs(filename)

    user = user_info.get("user")

    if not user:
        return {"crit4": "Không xác định được user", "detail": user_info}

    # User dịch vụ → nguy cơ exploit
    suspicious_users = ["www-data", "apache", "nginx", "mysql", "system", "network service"]

    if str(user).lower() in suspicious_users:
        return {"crit4": "File do user dịch vụ tạo — có thể bị exploit", "detail": user_info}

    return {"crit4": f"User tạo file: {user}", "detail": user_info}
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

# print(get_user_from_wazuh_logs("floss.exe"))
print(check_file_playbook("6d7f542ed46fcb02893a8672eb405d4b543e2a92db1ac22b5d53dbf303568b25", "C:/Users/admin/Downloads/mas_17-20230810T055912Z-001/mas_17-20230810T055912Z-001/mas_17/MAS_1.7_Password_1234/MAS_1.7/All-In-One-Version/MAS_AIO.cmd"))

    
