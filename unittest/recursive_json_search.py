from test_data import *
import logging

logger = logging.getLogger("json_search")

# ---- Policy (xem threat_model.md) – theo các trường thực tế trong test_data ----
ROLE_LEVEL = {"VIEWER": 1, "OPERATOR": 2, "ADMIN": 3}

_VIEWER_FIELDS = """
instanceId category status timestamp severity domain source priority type title
description enrichmentInfo issueDetails issue issueId issueSource issueCategory
issueName issueDescription issueEntity issueSeverity issuePriority issueSummary
issueTimestamp suggestedActions message steps impactedHosts hostName hostOs ssid
connectedInterface failedAttempts location siteId siteType area building
apsImpacted connectedDevice deviceDetails family errorCode role bootDateTime
collectionStatus interfaceCount lineCardCount memorySize platformId
reachabilityFailureReason reachabilityStatus series inventoryStatusDetail
collectionInterval softwareVersion roleSource hostname upTime lastUpdateTime
errorDescription tagCount lastUpdated neighborTopology detail
""".split()
# Định danh thiết bị / mạng (id xuất hiện ở cả event lẫn deviceDetails nên xếp OPERATOR)
_OPERATOR_FIELDS = """
id instanceUuid macAddress serialNumber managementIpAddress actualServiceId
issueEntityValue apManagerInterfaceIp associatedWlcIp lineCardId snmpContact
snmpLocation cisco360view assignedTo
""".split()
# Khoá/chuỗi xác thực (apiKey trong test_data chứa SNMP community string)
_ADMIN_FIELDS = "apiKey snmpCommunity snmpAuthKey snmpPrivKey password token".split()

FIELD_MIN_ROLE = {}
for _fields, _lvl in ((_VIEWER_FIELDS, 1), (_OPERATOR_FIELDS, 2), (_ADMIN_FIELDS, 3)):
    for _f in _fields:
        FIELD_MIN_ROLE[_f.lower()] = _lvl

DEFAULT_MIN_LEVEL = 2     # SR4: trường chưa khai báo -> OPERATOR trở lên
MAX_DEPTH = 32            # SR5
MAX_RESULTS = 1000        # SR5


def _can_read(field, value, level):
    name = str(field).lower()
    if name in FIELD_MIN_ROLE:
        return level >= FIELD_MIN_ROLE[name]
    if isinstance(value, (dict, list, tuple)):   # container chưa phân loại: cho duyệt
        return True
    return level >= DEFAULT_MIN_LEVEL


def _filter(value, level, depth=0):
    """SR2: loại các trường con mà role không được đọc."""
    if depth > MAX_DEPTH:
        raise ValueError("Max depth exceeded")
    if isinstance(value, dict):
        return {k: _filter(v, level, depth + 1)
                for k, v in value.items() if _can_read(k, v, level)}
    if isinstance(value, (list, tuple)):
        return [_filter(v, level, depth + 1) for v in value]
    return value


def _search(key, node, level, ret_val, path, depth):
    if depth > MAX_DEPTH:
        raise ValueError("Max depth exceeded")
    if not isinstance(node, (dict, list, tuple)) or id(node) in path:
        return                                   # scalar hoặc vòng lặp
    path.add(id(node))
    try:
        if isinstance(node, dict):
            for k, v in node.items():
                if not _can_read(k, v, level):   # SR3: không đi vào nhánh bị cấm
                    continue
                if k == key:
                    if len(ret_val) >= MAX_RESULTS:
                        return
                    ret_val.append({k: _filter(v, level)})
                _search(key, v, level, ret_val, path, depth + 1)   # đệ quy
        else:                                    # list / tuple
            for item in node:
                _search(key, item, level, ret_val, path, depth + 1)
    finally:
        path.discard(id(node))


def json_search(key, input_object, role="VIEWER"):
    level = ROLE_LEVEL.get(str(role).upper())
    if level is None:
        logger.warning("DENY invalid role")
        raise PermissionError("Role not authorized")
    required = FIELD_MIN_ROLE.get(str(key).lower())
    if required is not None and level < required:  # SR1
        logger.warning("DENY role=%s key=%s", role, key)
        raise PermissionError("Role not authorized for requested field")

    ret_val = []
    _search(key, input_object, level, ret_val, set(), 0)
    logger.info("SEARCH role=%s key=%s hits=%d", role, key, len(ret_val))  # SR6: không log value
    return ret_val


if __name__ == "__main__":
    print(json_search(key1, data))
    print(json_search(key2, data))   # key không tồn tại -> []