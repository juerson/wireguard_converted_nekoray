import base64
import os
import sys
import re
import ast


# 检查文件是否存在或大小为0，即文件无效
def check_unusable_file(file: str) -> None:
    if not os.path.exists(file) or os.stat(file).st_size == 0:
        sys.exit()


# 读取优选ip的result.csv文件
def read_csv_endpoints(csv_file: str) -> list[str]:
    endpoints = []
    with open(file=csv_file, mode='r', encoding='utf-8') as rf:
        next(rf)
        for line in rf:
            trim_line = line.strip()
            delay = trim_line.split(',')[-1].replace(' ', '').replace('ms', '')
            if int(delay) < 500:
                endpoint = trim_line.split(',')[0]
                endpoints.append(endpoint)
        return endpoints


# 读取wg-config.conf配置文件的信息
def read_wg_conf_kv(conf_file: str) -> dict[str, any]:
    with open(file=conf_file, mode='r', encoding='utf-8') as rf:
        wireguard_param = dict()
        for line in rf:
            trim_line = line.strip()
            if trim_line:
                if trim_line.startswith("PrivateKey"):
                    wireguard_param["PrivateKey"] = trim_line.replace(' ', '').replace("PrivateKey=", '')
                if trim_line.startswith("PublicKey"):
                    wireguard_param["PublicKey"] = trim_line.replace(' ', '').replace("PublicKey=", '')
                if trim_line.startswith("Address"):
                    wireguard_param["Address"] = trim_line.replace(' ', '').replace("Address=", '').split(',')
                if trim_line.startswith("MTU"):
                    wireguard_param["MTU"] = trim_line.replace(' ', '').replace("MTU=", '')
                if trim_line.startswith("Reserved"):
                    wireguard_param["Reserved"] = trim_line.replace(' ', '').replace("Reserved=", '')
        return wireguard_param


def is_valid_base64_4chars(s: str) -> bool:
    """判断是否是合法的 4 字符 Base64 字符串"""
    if not re.fullmatch(r"[A-Za-z0-9+/=]{4}", s):
        return False
    try:
        base64.b64decode(s, validate=True)
        return True
    except Exception:
        return False


def list_reserved(s: str) -> list[int]:
    """
    反向转换：
    - 4字符合法Base64 -> list[int]
    - "[121, 102, 72]" -> list[int]
    - 其他情况 -> []
    """
    s = s.strip()
    # 优先判断是否是 [n, n, n] 形式
    if s.startswith("[") and s.endswith("]"):
        try:
            lst = ast.literal_eval(s)  # 安全解析
            if isinstance(lst, list) and all(isinstance(x, int) for x in lst):
                return lst
        except (ValueError, SyntaxError):
            return []
        return []
    # 如果是4字符合法base64
    if is_valid_base64_4chars(s):
        try:
            decoded_bytes = base64.b64decode(s)
            return list(decoded_bytes)
        except Exception:
            return []
    return []


# 将从配置文件中读取到信息，写入到指定的JSON字符串中
def update_wg_kv(conf_file: str, default_mtu=None) -> str:
    param = read_wg_conf_kv(conf_file)
    # 获取*.conf的参数值
    private_key = param.get("PrivateKey")
    peer_public_key = param.get("PublicKey", "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=")
    address = param.get("Address", ["172.16.0.2/32"])
    if len(address) > 1:
        local_address = r"[\n    " + ',\n    '.join([r'  \"{ip}\"'.format(ip=item) for item in address]) + r"\n  ]"
    else:
        local_address = r'\"{ip}\"'.format(ip=address[0])
    mtu = param.get('MTU', 1360) if default_mtu is None else default_mtu
    reserved_value = param.get('Reserved', '')
    reserved = list_reserved(reserved_value)
    # 将*.conf的参数值更新进来
    custom_str = '{"_v":0,"addr":"127.0.0.1","cmd":[""],"core":"internal","cs":"{\\n  \\"interface_name\\": ' \
                 '\\"WARP\\",\\n  \\"local_address\\": #local_address,\\n  \\"mtu\\": #MUT值,\\n  ' \
                 '\\"peer_public_key\\": \\"#peer_public_key\\",\\n  \\"private_key\\": \\"#private_key\\",\\n  ' \
                 '\\"reserved\\": #reserved,\\n  \\"server\\": \\"IP地址\\",\\n  \\"server_port\\": 端口,\\n  ' \
                 '\\"system_interface\\": false,\\n  \\"tag\\": \\"proxy\\",\\n  \\"type\\": \\"wireguard' \
                 '\\"\\n}","mapping_port":0,"name":"别名","port":1080,"socks_port":0}'
    result = (custom_str.replace("#local_address", local_address)
              .replace("#MUT值", str(mtu))
              .replace("#peer_public_key", peer_public_key)
              .replace("#private_key", private_key)
              .replace("#reserved", str(reserved)))
    return result


if __name__ == '__main__':
    files = ["配置文件/wg-config.conf", "result.csv", "output-node.txt"]
    for file in files[:-1]:
        check_unusable_file(file)
    print("是否修改MTU值？输入内容为空时，就默认为配置文件的值，配置文件中没有MTU值，就使用1360；")
    while True:
        input_mtu = input("这里输入MTU值，取值范围为1280~1500：")
        if (input_mtu.isdigit() and 1280 <= int(input_mtu) <= 1500) or input_mtu.strip() == '':
            break
    base_str = None
    if input_mtu.isdigit():
        base_str = update_wg_kv(conf_file=files[0], default_mtu=input_mtu)
    else:
        base_str = update_wg_kv(conf_file=files[0])
    endpoints = read_csv_endpoints(csv_file=files[1])
    f = open(files[2], mode='w', encoding='utf-8')
    width = len(str(len(endpoints)))
    for i, endpoint in enumerate(endpoints):
        addr = endpoint.rsplit(':', 1)[0]
        ip = addr[1:-1] if addr.startswith('[') and addr.endswith(']') else addr  # 针对IPv6地址，写入JSON的server中要去掉中括号
        port = endpoint.rsplit(':', 1)[1]
        remarks = f"warp-{i + 1:0{width}d}"
        node = base_str.replace('别名', remarks).replace('IP地址', ip).replace('端口', port)
        encoded = base64.b64encode(node.encode('utf-8'), altchars=b'-_')
        encoded_str = str(encoded, encoding='utf-8')
        transport_protocol = "nekoray://custom#"
        nekoray_link = transport_protocol + encoded_str
        f.write(f"{nekoray_link}\n")
        f.flush()
    print(f"已经将节点的分享链接写入{files[2]}文件中！\n")
    f.close()
    os.system("pause")
