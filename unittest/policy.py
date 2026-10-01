# policy.py
# Quy định vai trò (role) nào được phép đọc giá trị của một trường (key)
# cụ thể trong dữ liệu JSON trả về bởi json_search().
#
# Sinh viên dùng bảng này để viết security test cho Yêu cầu 6: gọi
# json_search(key, data, role=...) với một role KHÔNG nằm trong danh sách
# cho phép đọc key đó, và kỳ vọng kết quả trả về là rỗng.

POLICY = {
    # ---- ADMIN: khoá/chuỗi xác thực (apiKey chứa SNMP community string) ----
    "apiKey": ["admin"],
    "snmpCommunity": ["admin"],
    "snmpAuthKey": ["admin"],
    "snmpPrivKey": ["admin"],
    "password": ["admin"],
    "token": ["admin"],
    # ---- ADMIN + OPERATOR: định danh thiết bị / mạng ----
    "id": ["admin", "operator"],
    "instanceUuid": ["admin", "operator"],
    "macAddress": ["admin", "operator"],
    "serialNumber": ["admin", "operator"],
    "managementIpAddress": ["admin", "operator"],
    "actualServiceId": ["admin", "operator"],
    "issueEntityValue": ["admin", "operator"],
    "apManagerInterfaceIp": ["admin", "operator"],
    "associatedWlcIp": ["admin", "operator"],
    "lineCardId": ["admin", "operator"],
    "snmpContact": ["admin", "operator"],
    "snmpLocation": ["admin", "operator"],
    "cisco360view": ["admin", "operator"],
    "assignedTo": ["admin", "operator"],
    # ---- Cả 3 role: thông tin sự cố, không nhạy cảm ----
    "instanceId": ["admin", "operator", "viewer"],
    "category": ["admin", "operator", "viewer"],
    "status": ["admin", "operator", "viewer"],
    "timestamp": ["admin", "operator", "viewer"],
    "severity": ["admin", "operator", "viewer"],
    "domain": ["admin", "operator", "viewer"],
    "source": ["admin", "operator", "viewer"],
    "priority": ["admin", "operator", "viewer"],
    "type": ["admin", "operator", "viewer"],
    "title": ["admin", "operator", "viewer"],
    "description": ["admin", "operator", "viewer"],
    "enrichmentInfo": ["admin", "operator", "viewer"],
    "issueDetails": ["admin", "operator", "viewer"],
    "issue": ["admin", "operator", "viewer"],
    "issueId": ["admin", "operator", "viewer"],
    "issueSource": ["admin", "operator", "viewer"],
    "issueCategory": ["admin", "operator", "viewer"],
    "issueName": ["admin", "operator", "viewer"],
    "issueDescription": ["admin", "operator", "viewer"],
    "issueEntity": ["admin", "operator", "viewer"],
    "issueSeverity": ["admin", "operator", "viewer"],
    "issuePriority": ["admin", "operator", "viewer"],
    "issueSummary": ["admin", "operator", "viewer"],
    "issueTimestamp": ["admin", "operator", "viewer"],
    "suggestedActions": ["admin", "operator", "viewer"],
    "message": ["admin", "operator", "viewer"],
    "steps": ["admin", "operator", "viewer"],
    "impactedHosts": ["admin", "operator", "viewer"],
    "hostName": ["admin", "operator", "viewer"],
    "hostOs": ["admin", "operator", "viewer"],
    "ssid": ["admin", "operator", "viewer"],
    "connectedInterface": ["admin", "operator", "viewer"],
    "failedAttempts": ["admin", "operator", "viewer"],
    "location": ["admin", "operator", "viewer"],
    "siteId": ["admin", "operator", "viewer"],
    "siteType": ["admin", "operator", "viewer"],
    "area": ["admin", "operator", "viewer"],
    "building": ["admin", "operator", "viewer"],
    "apsImpacted": ["admin", "operator", "viewer"],
    "connectedDevice": ["admin", "operator", "viewer"],
    "deviceDetails": ["admin", "operator", "viewer"],
    "family": ["admin", "operator", "viewer"],
    "errorCode": ["admin", "operator", "viewer"],
    "role": ["admin", "operator", "viewer"],
    "bootDateTime": ["admin", "operator", "viewer"],
    "collectionStatus": ["admin", "operator", "viewer"],
    "interfaceCount": ["admin", "operator", "viewer"],
    "lineCardCount": ["admin", "operator", "viewer"],
    "memorySize": ["admin", "operator", "viewer"],
    "platformId": ["admin", "operator", "viewer"],
    "reachabilityFailureReason": ["admin", "operator", "viewer"],
    "reachabilityStatus": ["admin", "operator", "viewer"],
    "series": ["admin", "operator", "viewer"],
    "inventoryStatusDetail": ["admin", "operator", "viewer"],
    "collectionInterval": ["admin", "operator", "viewer"],
    "softwareVersion": ["admin", "operator", "viewer"],
    "roleSource": ["admin", "operator", "viewer"],
    "hostname": ["admin", "operator", "viewer"],
    "upTime": ["admin", "operator", "viewer"],
    "lastUpdateTime": ["admin", "operator", "viewer"],
    "errorDescription": ["admin", "operator", "viewer"],
    "tagCount": ["admin", "operator", "viewer"],
    "lastUpdated": ["admin", "operator", "viewer"],
    "neighborTopology": ["admin", "operator", "viewer"],
    "detail": ["admin", "operator", "viewer"],
}

# ---- Các thông số bổ sung theo threat_model.md ----
VALID_ROLES = ("admin", "operator", "viewer")
DEFAULT_ROLES = ["admin", "operator"]   # SR4: trường chưa khai báo -> chỉ operator trở lên
MAX_DEPTH = 32                          # SR5: giới hạn độ sâu
MAX_RESULTS = 1000                      # SR5: giới hạn số kết quả

_POLICY_LC = {k.lower(): v for k, v in POLICY.items()}   # so khớp không phân biệt hoa/thường


def normalize_role(role):
    """Trả về role dạng chữ thường nếu hợp lệ, ngược lại None."""
    if isinstance(role, str) and role.lower() in VALID_ROLES:
        return role.lower()
    return None


def allowed_roles(key):
    """Danh sách role được đọc key; None nếu key chưa khai báo trong POLICY."""
    return _POLICY_LC.get(str(key).lower())


def can_read(key, value, role):
    """Role có được đọc trường `key` (có giá trị `value`) hay không."""
    roles = allowed_roles(key)
    if roles is not None:
        return role in roles
    if isinstance(value, (dict, list, tuple)):   # container chưa phân loại: cho duyệt,
        return True                              # từng trường con vẫn bị kiểm tra riêng
    return role in DEFAULT_ROLES