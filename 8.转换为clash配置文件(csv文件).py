import json
import os
import sys
import re
import base64
from collections import OrderedDict


# 检查文件是否存在或大小为0，即文件无效
def check_file_exist_or_zero_size(file):
    if not os.path.exists(file) or os.stat(file).st_size == 0:
        sys.exit()


# 读取wg-config.conf配置文件的信息
def read_wireguard_key_parameters(conf_file):
    with open(file=conf_file, mode='r', encoding='utf-8') as f:
        wireguard_param = dict()
        for line in f:
            if line:
                if line.startswith("PrivateKey"):
                    wireguard_param["PrivateKey"] = line.strip().replace(' ', '').replace("PrivateKey=", '')
                if line.startswith("PublicKey"):
                    wireguard_param["PublicKey"] = line.strip().replace(' ', '').replace("PublicKey=", '')
                if line.startswith("Address"):
                    wireguard_param["Address"] = line.strip().replace(' ', '').replace("Address=", '').split(',')
                if line.startswith("MTU"):
                    wireguard_param["MTU"] = line.strip().replace(' ', '').replace("MTU=", '')
                if line.startswith("Reserved"):
                    wireguard_param["Reserved"] = line.strip().replace(' ', '').replace("Reserved=", '')
        return wireguard_param


# 读取优选ip的result.csv文件
def read_ip_endpoints(csv_file):
    endpoints = []
    with open(file=csv_file, mode='r', encoding='utf-8') as rf:
        next(rf)
        for line in rf:
            delay = line.strip().split(',')[-1].replace(' ', '').replace('ms', '')
            if int(delay) < 500:
                endpoint = line.strip().split(',')[0]
                endpoints.append(endpoint)
        return endpoints


# 使用正则表达检查IP的版本（IPv4、IPv6）
def ip_version(ip):
    ipv4_pattern = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    ipv6_pattern = re.compile(r'^(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:))$')
    if ipv4_pattern.match(ip):
        return "IPv4"
    elif ipv6_pattern.match(ip):
        return "IPv6"
    else:
        return "Invalid"


if __name__ == '__main__':
    """ 读取外部文件的数据 """
    files = ["配置文件/wg-config.conf", "result.csv"]
    # 检查文件是否存在
    for file in files:
        check_file_exist_or_zero_size(file)
    param = read_wireguard_key_parameters(files[0])
    """ 处理参数，准备给wireguard节点对应的clash配置使用 """
    # 获取 private-key 的值
    private_key = param.get("PrivateKey")
    private_key = private_key if private_key else "+HfkMSyh7obEkX4J8Qa7Xk77CLVn45AW4CdBbnFNaGc="  # 找不到就使用这个私钥
    # 获取 public-key 的值
    public_key = param.get("PublicKey")
    public_key = public_key if public_key else "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="  # 找不到就使用这个公钥
    # 获取 reserved 的值，貌似不支持4个字符的reserved值
    """
    Reserved = param.get("Reserved")
    reserved = ""
    if Reserved.startswith('[') and Reserved.endswith(']') and "," in Reserved:
        reserved = [int(number) for number in Reserved.strip('[').strip(']').split(',')]
    """
    # 获取 mtu 的值
    mtu = param.get("MTU")
    mtu = int(mtu) if mtu else 1280  # 找不到，就使用1280代替
    # 获取clash中wireguard配置中，需要的 ipv6、ip -> ipv4
    ipv4_str: str = ""
    ipv6_str: str = ""
    Address = param.get("Address")
    if Address is None or Address == "":
        ipv4_str = "172.16.0.2"
    if isinstance(Address, list):
        ipv4_addr = Address[0].split("/")[0]
        ipv4_str = ipv4_addr if ip_version(ipv4_addr) == "IPv4" else "172.16.0.2"  # 确保数据是ipv4的地址，否则使用172.16.0.2
        ipv6_addr = Address[1].split("/")[0]
        ipv6_str = ipv6_addr if ip_version(ipv6_addr) == "IPv6" else ""  # 确保数据是ipv6的地址，否则为空

    """ 读取result.csv的数据 """
    endpoints: list[str] = read_ip_endpoints(files[1])

    # 待插入clash中的wireguard配置模板
    wireguard_str: str = """{"name":"warp-001","type":"wireguard","server":"162.159.192.1","port":2408,"ip":"172.16.0.2","ipv6":"","private-key":"","public-key":"bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=","pre-shared-key":"","reserved":"","udp":true,"mtu":1280,"remote-dns-resolve":true,"dns":["1.1.1.1","1.0.0.1","2606:4700:4700::1111","2606:4700:4700::1001"]}"""
    wireguard_dict: dict = json.loads(wireguard_str)
    wireguard_nodes: list = []
    wireguard_names: list = []
    # 使用OrderedDict对endpoints进行去重，并保持顺序，防止生成相同的节点
    deduplicated_list = OrderedDict.fromkeys(endpoints)
    # 只处理前面300个，防止上千、上万的数据写入一个clash配置文件中，clash能处理？不会导致软件崩溃？
    data_list = list(deduplicated_list)[:300]
    for i, ip_with_port in enumerate(data_list):
        [server, port] = ip_with_port.rsplit(":", 1)
        index = str(i + 1).zfill(len(str(len(deduplicated_list))))
        proxy_name: str = f"warp{index}-{str(server).strip('[').strip(']')}"
        # 将数据写入wireguard_dict中
        wireguard_dict["name"] = proxy_name
        wireguard_dict["server"] = str(server).strip("[").strip("]")  # 去掉ipv6的中括号
        wireguard_dict["port"] = int(port)
        wireguard_dict["ip"] = ipv4_str
        wireguard_dict["ipv6"] = ipv6_str
        wireguard_dict["private-key"] = private_key
        wireguard_dict["public-key"] = public_key
        # 添加reserved值，不管是数组类型的还是字符串类型的reserved值，会出现无法联网/网络慢
        # wireguard_dict["reserved"] = reserved
        wireguard_dict["mtu"] = int(mtu)
        # 将字典转换为 JSON 字符串(把字典中的True -> true)
        wireguard_json_str: str = json.dumps(wireguard_dict)

        # node_prefix: str = "  - "
        node_prefix: str = base64.b64decode("ICAtIA==").decode("utf-8")
        wireguard_nodes.append(f"{node_prefix}{wireguard_json_str}")

        # proxy_name_prefix = "      - "
        proxy_name_prefix: str = base64.b64decode("ICAgICAgLSA=").decode("utf-8")
        wireguard_names.append(f"{proxy_name_prefix}{proxy_name}")
    output_file = "output-clash.yaml"
    # 替换clash配置模板中指定的字符串
    with open('配置文件/clash.yaml', mode='r', encoding='utf-8') as rf, open(output_file, 'w', encoding='utf-8') as wf:
        clash = rf.read()

        # 普通的写法
        # replace_proxy_node = "  - {name: 127.0.0.1:1080, server: 127.0.0.1, port: 1080, type: ss, cipher: aes-128-gcm, password: abc123456}"
        # replace_proxy_name = "      - 127.0.0.1:1080"

        # base64的写法：使用其它工具，将字符串进行base64编码，然后解码使用，防止误删字符，同时进行数据保密，没有base64解码就不知道这个数据代表什么
        replace_proxy_node = base64.b64decode("ICAtIHtuYW1lOiAxMjcuMC4wLjE6MTA4MCwgc2VydmVyOiAxMjcuMC4wLjEsIHBvcnQ6IDEwODAsIHR5cGU6IHNzLCBjaXBoZXI6IGFlcy0xMjgtZ2NtLCBwYXNzd29yZDogYWJjMTIzNDU2fQ==").decode("utf-8")
        replace_proxy_name = base64.b64decode("ICAgICAgLSAxMjcuMC4wLjE6MTA4MA==").decode("utf-8")

        clash_result = clash.replace(replace_proxy_node, "\n".join(wireguard_nodes)).replace(replace_proxy_name, "\n".join(wireguard_names))
        print(clash_result)
        wf.write(clash_result)
        os.system("pause")