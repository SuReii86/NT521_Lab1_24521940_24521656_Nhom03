from test_data import * 
def json_search(key, input_object):
    # Danh sách kết quả của lần gọi này (mỗi phần tử là một cặp {key: value})
    ret_val = []

    # Trường hợp 1: đối tượng là dict -> duyệt từng cặp key/value
    if isinstance(input_object, dict):
        for k, v in input_object.items():
            # Nếu key hiện tại trùng key cần tìm -> lưu lại cặp {key: value}
            if k == key:
                ret_val.append({k: v})
            # Đệ quy vào value (có thể là dict/list lồng bên trong),
            # rồi nối kết quả tìm được vào danh sách chung
            ret_val.extend(json_search(key, v))

    # Trường hợp 2: đối tượng là list/tuple -> duyệt từng phần tử
    elif isinstance(input_object, (list, tuple)):
        for item in input_object:
            # Mỗi phần tử có thể là dict/list khác -> đệ quy và nối kết quả
            ret_val.extend(json_search(key, item))

    # Trường hợp 3 (ngầm): giá trị đơn như str, int, None...
    # không rơi vào nhánh nào -> trả về [] (điều kiện dừng của đệ quy)
    return ret_val

if __name__ == "__main__":
    print(json_search(key1, data))
    print(json_search(key2, data))