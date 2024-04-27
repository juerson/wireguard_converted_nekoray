import base64
import os
import sys


# 检查文件是否存在或大小为0，即文件无效
def check_file_exist_or_zero_size(file):
    if not os.path.exists(file) or os.stat(file).st_size == 0:
        sys.exit()


# 读取优选ip的ip.txt文件
def read_ip_endpoints(txt_file):
    endpoints = []
    with open(file=txt_file, mode='r', encoding='utf-8') as rf:
        for item in rf.readlines():
            if item.strip() != "":
                endpoints.append(item.strip())
        return endpoints


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
        return wireguard_param


# 将从配置文件中读取到信息，写入到指定的JSON字符串中
def update_base_info(conf_file, MTU=None):
    param = read_wireguard_key_parameters(conf_file)
    peer_public_key = param["PublicKey"].strip()
    private_key = param["PrivateKey"].strip()
    Address = param.get("Address")
    # if条件针对wireguard配置中，Address行的值有多个值或一个值的情况
    if len(Address) > 1:  # 多个值（一般是IPv4 CIDR 和 IPv6 CIDR）
        local_address = r"[\n" + ','.join([r'    \"{ip}\"'.format(ip=item) for item in Address]) + r"\n  ]"
    else:  # 只有一个值
        local_address = r'\"{ip}\"'.format(ip=Address[0])
    MTU = param.get('MTU', 1408) if MTU is None else MTU
    nekoray_str_json = '{"_v":0,"addr":"127.0.0.1","cmd":[""],"core":"internal","cs":"{\\n  \\"interface_name\\": ' \
                       '\\"WARP\\",\\n  \\"local_address\\": #local_address,\\n' \
                       '  \\"mtu\\": #MUT值,\\n  \\"peer_public_key\\": \\"#peer_public_key\\",\\n  \\"private_key\\":' \
                       ' \\"#private_key\\",\\n  \\"server\\": \\"IP地址\\",\\n  \\"server_port\\": 端口,\\n  ' \
                       '\\"system_interface\\": false,\\n  \\"tag\\": \\"proxy\\",\\n  \\"type\\": \\"wireguard' \
                       '\\"\\n}","mapping_port":0,"name":"别名","port":1080,"socks_port":0}'
    update_key = nekoray_str_json.replace('#peer_public_key', peer_public_key).replace('#private_key', private_key)
    update_address = update_key.replace('#local_address', local_address).replace('#MUT值', str(MTU))
    return update_address


if __name__ == '__main__':
    """判断文件是否存在或文件的大小为0"""
    files = ["配置文件/wg-config.conf", "ip.txt"]
    for file in files:
        check_file_exist_or_zero_size(file)  # 检查文件是否存在
    """MTU值的修改"""
    print("是否修改MTU值？输入内容为空时，就默认为配置文件的值，配置文件中没有MTU值，就使用1408；")
    while True:
        input_mtu = input("这里输入MTU值，取值范围为1280~1500：")
        if (input_mtu.isdigit() and 1280 <= int(input_mtu) <= 1500) or input_mtu.strip() == '':
            break
    input_country = input('添加节点名称或别名的前缀吗？(比如，CN)：').strip()
    country = f'{input_country.strip()}_' if input_country != '' else ''
    base_str = None
    if input_mtu.isdigit():
        base_str = update_base_info(files[0], MTU=input_mtu)  # 调用函数
    else:
        base_str = update_base_info(files[0])  # 调用函数
    endpoints = read_ip_endpoints(txt_file=files[1])
    output_file = 'output-node.txt'  # nekoray节点保存到这里
    f = open(output_file, mode='w', encoding='utf-8')
    for endpoint in endpoints:
        ip = endpoint.rsplit(':', 1)[0]
        ip = ip[1:-1] if ip.startswith('[') and ip.endswith(']') else ip  # 针对IPv6地址，写入JSON的server中要去掉中括号
        port = endpoint.rsplit(':', 1)[1]
        remarks = f"{ip}:{port}" if ip.count(":") == 0 else f"[{ip}]:{port}"  # 节点的别名、节点的名称（不重要，ipv6的加上中括号）
        node = base_str.replace('别名', f'{country}{remarks}').replace('IP地址', ip).replace('端口', port)
        encoded = base64.b64encode(node.encode('utf-8'), altchars=b'-_')
        encoded_str = str(encoded, encoding='utf-8')
        transport_protocol = "nekoray://custom#"  # 在base64编码好的字符串前缀添加这个前缀（NekoBox软件专用的前缀）
        nekoray_node = transport_protocol + encoded_str
        f.write(f"{nekoray_node}\n")
        f.flush()
    print(f"已经将节点写入{output_file}文件中！\n")
    f.close()
    os.system("pause")
