from collections import OrderedDict
import base64
import json
import os
import sys
import re


# 检查文件是否存在或大小为0，即文件无效
def check_unusable_file(file: str) -> None:
    if not os.path.exists(file) or os.stat(file).st_size == 0:
        sys.exit()


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


# 读取优选ip的ip.txt文件
def read_txt_endpoints(txt_file: str) -> list[str]:
    endpoints = []
    with open(file=txt_file, mode='r', encoding='utf-8') as rf:
        for line in rf.readlines():
            trim_line = line.strip()
            if trim_line != "":
                endpoints.append(trim_line)
        return endpoints


# 使用正则表达检查IP的版本（IPv4、IPv6）
def ip_version(ip: str) -> str:
    ipv4_pattern = re.compile(
        r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    ipv6_pattern = re.compile(
        r'^(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:))$')
    if ipv4_pattern.match(ip):
        return "IPv4"
    elif ipv6_pattern.match(ip):
        return "IPv6"
    else:
        return "Invalid"


if __name__ == '__main__':
    """ 读取外部文件的数据 """
    files = ["配置文件/wg-config.conf", "ip.txt", "output-clash.yaml"]
    for file in files[:-1]:
        check_unusable_file(file)  # 检查文件是否存在
    param = read_wg_conf_kv(files[0])
    """ 获取*.conf的参数值 """
    private_key = param.get("PrivateKey", "+HfkMSyh7obEkX4J8Qa7Xk77CLVn45AW4CdBbnFNaGc=")
    public_key = param.get("PublicKey", "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=")
    # """
    reserved_value = param.get("Reserved")
    reserved = reserved_value
    if reserved_value.startswith('[') and reserved_value.endswith(']') and "," in reserved_value:
        reserved = [int(number) for number in reserved_value.strip('[').strip(']').split(',')]
    # """
    mtu_value = param.get("MTU")
    mtu = int(mtu_value) if mtu_value else 1360  # 找不到，就使用1360代替
    ipv4_str: str = ""
    ipv6_str: str = ""
    address_value = param.get("Address")
    if address_value is None or address_value == "":
        ipv4_str = "172.16.0.2"
    if isinstance(address_value, list):
        ipv4_addr = address_value[0].split("/")[0]
        ipv4_str = ipv4_addr if ip_version(ipv4_addr) == "IPv4" else "172.16.0.2"  # 确保数据是ipv4的地址，否则使用172.16.0.2
        ipv6_addr = address_value[1].split("/")[0]
        ipv6_str = ipv6_addr if ip_version(ipv6_addr) == "IPv6" else ""  # 确保数据是ipv6的地址，否则为空

    """ 读取ip.txt的数据 """
    endpoints: list[str] = read_txt_endpoints(files[1])

    wireguard_nodes: list = []
    wireguard_names: list = []

    # 使用OrderedDict对endpoints进行去重，并保持顺序，防止生成相同的节点
    deduplicated_list = OrderedDict.fromkeys(endpoints)
    # 只处理前面80个，防止上千、上万的数据写入一个clash配置文件中，clash能处理？不会导致软件崩溃？
    data_list = list(deduplicated_list)[:80]
    width = len(str(len(data_list)))
    for i, ip_with_port in enumerate(data_list):
        [server, port] = ip_with_port.rsplit(":", 1)
        trim_server = str(server).strip("[").strip("]")
        proxy_name = f"warp{i + 1:0{width}d}-{trim_server}"
        wireguard_dict = {
            "name": proxy_name,
            "type": "wireguard",
            "server": trim_server,
            "port": int(port),
            "ip": ipv4_str,
            "ipv6": ipv6_str,
            "private-key": private_key,
            "public-key": public_key,
            "reserved": reserved,
            "udp": True,
            "mtu": int(mtu)
        }
        # proxy_name_prefix = "      - "
        proxy_name_prefix: str = base64.b64decode("ICAgICAgLSA=").decode("utf-8")
        wireguard_names.append(f"{proxy_name_prefix}{proxy_name}")

        # node_prefix: str = "  - "
        node_prefix: str = base64.b64decode("ICAtIA==").decode("utf-8")
        wg_json_str: str = json.dumps(wireguard_dict)  # 将字典转换为 JSON 字符串(把字典中的True -> true)
        wireguard_nodes.append(f"{node_prefix}{wg_json_str}")

    # 替换clash配置模板中指定的字符串
    with (open('配置文件/clash.yaml', mode='r', encoding='utf-8') as rf, open(files[2], 'w', encoding='utf-8') as wf):
        clash = rf.read()

        # 1、普通的写法
        # replace_proxy_node = "  - {name: 127.0.0.1:1080, server: 127.0.0.1, port: 1080, type: ss, cipher: aes-128-gcm, password: abc123456}"
        # replace_proxy_name = "      - 127.0.0.1:1080"

        # 2、base64的写法：使用其它工具，将字符串进行base64编码，然后解码使用
        raw_node = base64.b64decode(
            "ICAtIHtuYW1lOiAxMjcuMC4wLjE6MTA4MCwgc2VydmVyOiAxMjcuMC4wLjEsIHBvcnQ6IDEwODAsIHR5cGU6IHNzLCBjaXBoZXI6IGFlcy0xMjgtZ2NtLCBwYXNzd29yZDogYWJjMTIzNDU2fQ==").decode(
            "utf-8")
        raw_name = base64.b64decode("ICAgICAgLSAxMjcuMC4wLjE6MTA4MA==").decode("utf-8")

        clash_result = clash.replace(raw_node, "\n".join(wireguard_nodes)).replace(raw_name, "\n".join(wireguard_names))
        print(clash_result)
        wf.write(clash_result)
        os.system("pause")
