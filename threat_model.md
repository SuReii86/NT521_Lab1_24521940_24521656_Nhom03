# Threat Model – `json_search`

## (a) Actor / Role
| Role | Mục đích gọi hàm | Trường được đọc |
|---|---|---|
| VIEWER | Xem tóm tắt sự cố | `issueSummary`, `severity`, `deviceName` |
| OPERATOR | Vận hành thiết bị | + `ipAddress`, `macAddress`, `serialNumber` |
| ADMIN | Quản trị thiết bị | + `snmpCommunity`, `snmpAuthKey`, `snmpPrivKey`, `password`, `token` |
| ANONYMOUS / role không hợp lệ | Không có | Không được gọi hàm |

## (b) Asset nhạy cảm
- Chuỗi xác thực SNMP: community string, auth key, priv key
- Định danh thiết bị: serial number, MAC, IP
- Password / token nằm lẫn trong dữ liệu cấu hình

### Ánh xạ vào trường thực tế trong `test_data.py`
- **ADMIN**: `apiKey` (chứa SNMP community string)
- **OPERATOR**: `macAddress`, `serialNumber`, `managementIpAddress`, `actualServiceId`, `issueEntityValue`, `apManagerInterfaceIp`, `associatedWlcIp`, `lineCardId`, `instanceUuid`, `id`, `cisco360view`, `snmpContact`, `snmpLocation`, `assignedTo`
- **VIEWER**: các trường còn lại đã khai báo (vd. `issueSummary`, `severity`, `title`, `hostname`...)
- Lưu ý: `issueSummary`, `description` là văn bản tự do và có thể chứa IP; policy theo key không lọc được nội dung bên trong chuỗi.

## (c) Trust boundary bị bỏ qua
Ranh giới giữa **caller (có role)** và **dữ liệu JSON thô**. Nếu hàm không kiểm tra role
thì mọi caller đều được đối xử như ADMIN, và hàm duyệt vào cả các nhánh nhạy cảm.

## (d) Threats (STRIDE)
| ID | Nhóm | Mô tả |
|---|---|---|
| T1 | Information Disclosure | Tìm trực tiếp key nhạy cảm (`snmpCommunity`), hoặc tìm key vô hại (`devices`) nhưng value là dict chứa key nhạy cảm lồng bên trong |
| T2 | Elevation of Privilege | VIEWER lấy được dữ liệu dành cho ADMIN vì không có kiểm tra role |
| T3 | Denial of Service | JSON quá sâu, tham chiếu vòng, quá nhiều kết quả |
| T4 | Information Disclosure | Log hoặc lỗi chứa giá trị nhạy cảm |

## Security Requirements
- **SR1**: Hệ thống chỉ trả về giá trị của trường X cho các role nằm trong danh sách được phép truy cập trường đó; ngược lại raise `AccessDenied`.
- **SR2**: Value dạng dict/list phải được lọc đệ quy, loại các trường con mà role không được đọc.
- **SR3**: Không duyệt vào nhánh có key cha mà role không được phép đọc.
- **SR4**: Trường chưa khai báo: giá trị đơn mặc định chỉ OPERATOR trở lên (fail-safe), role thấp hơn nhận kết quả rỗng; container vẫn được duyệt nhưng từng trường con bị kiểm tra riêng.
- **SR5**: Giới hạn độ sâu, số kết quả; phát hiện tham chiếu vòng.
- **SR6**: Ghi audit log (role, key, số kết quả) nhưng không ghi value.
- **SR7**: Role mặc định khi không truyền là mức thấp nhất (VIEWER).
