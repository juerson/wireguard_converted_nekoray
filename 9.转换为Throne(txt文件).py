# Throne v1.2.4

from urllib.parse import quote
import base64
import re
import os
import sys
import ast


def check_unusable_file(file: str) -> None:
    if not os.path.exists(file) or os.stat(file).st_size == 0:
        sys.exit()


def read_txt_endpoints(txt_file: str) -> list[str]:
    endpoints = []
    with open(file=txt_file, mode='r', encoding='utf-8') as rf:
        for line in rf.readlines():
            trim_line = line.strip()
            if trim_line != "":
                endpoints.append(trim_line)
        return endpoints


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


if __name__ == '__main__':
    files = ["配置文件/wg-config.conf", "ip.txt", "output-node.txt"]
    # 检查两个输入文件是否可用
    for file in files[:-1]:
        check_unusable_file(file)
    # (可选)修改MTU值
    print("是否自定义MTU值？默认为(*.conf)配置文件的MTU值或1360；")
    while True:
        in_mtu = input("这里输入MTU值，取值范围为1280~1500：").strip()
        if (in_mtu.isdigit() and 1280 <= int(in_mtu) <= 1500) or in_mtu == '':
            break
    # 读取文件
    param = read_wg_conf_kv(files[0])
    endpoints = read_txt_endpoints(files[1])
    # 获取*.conf的参数值
    prik = param.get("PrivateKey")
    pubk = param.get("PublicKey", "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=")
    addr = param.get("Address", ["172.16.0.2/32"])
    mtu = param.get('MTU', 1360) if in_mtu == "" else in_mtu
    reserved_value = param.get("Reserved", "")
    reserved = list_reserved(str(reserved_value))  # 统一转换为list类型
    rsvd = "-".join(map(str, reserved))
    # 输出文件
    f = open(files[2], mode='w', encoding='utf-8')
    width = len(str(len(endpoints)))
    for i, endpoint in enumerate(endpoints):
        ip = endpoint.rsplit(':', 1)[0]  # ipv6的带中括号
        port = endpoint.rsplit(':', 1)[1]
        remarks = f"warp-{i + 1:0{width}d}"
        throne_link = f'wg://{ip}:{port}?private_key={prik}&public_key={pubk}&reserved={rsvd}&persistent_keepalive_interval=30&mtu={mtu}&local_address={"-".join(addr)}#{quote(remarks)}'
        f.write(f"{throne_link}\n")
        f.flush()
    print(f"已经将节点的分享链接写入{files[2]}文件中！\n")
    f.close()
    os.system("pause")