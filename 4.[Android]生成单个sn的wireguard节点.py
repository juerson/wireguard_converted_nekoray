from dataclasses import field, dataclass
import pyperclip  # 将指定的运行结果自动复制到剪切板
import base64
import sys
import zlib
import re
import ast  # 安全解析str成list


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


# 判断是否为IP地址（IPv4或IPv6）
def is_ip_address(ip_addr: str) -> bool:
    """ 匹配 IPv4 和 IPv6 地址 """
    ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    ipv6_pattern = r'^(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:))$'
    try:
        addr = ip_addr.rsplit(":", 1)[0]
        ip = addr[1:-1] if addr.startswith('[') and addr.endswith(']') else addr
        port = ip_addr.rsplit(':', 1)[1] if ip_addr.count(":") == 1 or (
                ip_addr.count(":") > 3 and "]:" in ip_addr) else None
        if re.match(ipv4_pattern, ip) and (port.isdigit() and int(port) >= 80):
            ipv4 = re.match(ipv4_pattern, ip).group(0)
            return True
        elif re.match(ipv6_pattern, ip) and (port.isdigit() and int(port) >= 80):
            ipv6 = re.match(ipv6_pattern, ip).group(0)
            return True
    except Exception as e:
        pass
    return False


def is_valid_base64_4chars(s: str) -> bool:
    """判断是否是合法的 4 字符 Base64 字符串"""
    if not re.fullmatch(r"[A-Za-z0-9+/=]{4}", s):
        return False
    try:
        base64.b64decode(s, validate=True)
        return True
    except Exception:
        return False


def base64_reserved(s: str) -> str:
    s = s.strip()
    # 如果原来就是合法的 4 字符 Base64
    if is_valid_base64_4chars(s):
        return s
    # 如果是带中括号的数组格式
    if s.startswith("[") and s.endswith("]"):
        try:
            lst = ast.literal_eval(s)
            if isinstance(lst, list) and all(isinstance(i, int) for i in lst):
                b64_str = base64.b64encode(bytes(lst)).decode("ascii")
                return b64_str if is_valid_base64_4chars(b64_str) else ""
        except ValueError:
            return ""
    # 其它情况
    return ""


def encode_sn_str(s: str) -> bytes:
    if not s:
        return b'\x81'
    if len(s) == 1:
        return b'\x82' + s.encode()
    ret = s.encode()
    ret = ret[:-1] + (ret[-1] | 0x80).to_bytes(1, 'little')
    return ret


def p32(n: int):
    return n.to_bytes(4, 'little')


def p8(n: int):
    return n.to_bytes(1, 'little')


@dataclass(init=True, repr=True)
class SnBase:
    def serialize(self) -> bytes:
        ret = b''
        for _, v in self.__dict__.items():
            ret += self.obj_serialize(v)
        return ret

    @classmethod
    def obj_serialize(cls, obj) -> bytes:
        ret = b''
        match type(obj):
            case __builtins__.str:
                ret += encode_sn_str(obj)
            case __builtins__.bool:
                ret += p8(int(obj))
            case __builtins__.int:
                ret += p32(obj)
            case _:
                if isinstance(obj, SnBase):
                    ret += obj.serialize()
        return ret


@dataclass(init=True, repr=True)
class SnServer(SnBase):
    server_address: str = '162.159.192.10'
    server_port: int = 2408


@dataclass(init=True, repr=True)
class SerializeWG(SnBase):
    version: int = 1
    server: SnServer = field(default_factory=SnServer)
    localAddress: str = "172.16.0.2/32"
    privateKey: str = ''
    peerPublicKey: str = 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo='
    peerPreSharedKey: str = ''
    mtu: int = 1420
    reserved: str = ""

    def serialize(self) -> bytes:
        ret = b''
        ret += self.obj_serialize(self.version)
        ret += self.obj_serialize(self.server)
        ret += self.obj_serialize(self.localAddress)
        ret += self.obj_serialize(self.privateKey)
        ret += self.obj_serialize(self.peerPublicKey)
        ret += self.obj_serialize(self.peerPreSharedKey)
        ret += self.obj_serialize(self.mtu)
        ret += self.obj_serialize(self.reserved)
        return ret


@dataclass(init=True, repr=True)
class SnMeta(SnBase):
    extraVersion: int = 2
    name: str = ''
    customOutboundJson: str = ''
    customConfigJson: str = ''


@dataclass(init=True, repr=True)
class Wireguard(SnBase):
    serialize_wg: SerializeWG = field(default_factory=SerializeWG)
    sn_meta: SnMeta = field(default_factory=SnMeta)

    def __str__(self) -> str:
        # print(self.serialize())
        return f'sn://wg?{base64.urlsafe_b64encode(zlib.compress(self.serialize())).decode()}'


if __name__ == '__main__':
    param = read_wg_conf_kv("配置文件/wg-config.conf")
    private_key = param.get("PrivateKey", "+HfkMSyh7obEkX4J8Qa7Xk77CLVn45AW4CdBbnFNaGc=")
    public_key = param.get("PublicKey", "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=")
    mtu = param.get("MTU", 1360)
    address_value = param.get("Address", ["172.16.0.2/32"])
    local_address = ",".join(address_value)
    reserved_str = param.get("Reserved", "")
    reserved = base64_reserved(str(reserved_str))
    while True:
        while True:
            input_endpoint = input("输入优选IP(格式：162.159.192.10:891)，输入q、quit、exit退出程序：").strip()
            state = is_ip_address(input_endpoint)
            if state:
                break
            if input_endpoint.lower() in ["q", "quit", "exit"]:
                sys.exit()
        addr = input_endpoint.rsplit(":", 1)[0]
        ip = addr[1:-1] if addr.startswith('[') and addr.endswith(']') else addr  # 去掉IPv6的中括号
        port = input_endpoint.rsplit(':', 1)[1]
        serialize_obj = SerializeWG(server=SnServer(ip, int(port)),
                                    localAddress=local_address,
                                    privateKey=private_key,
                                    peerPublicKey=public_key,
                                    mtu=int(mtu), reserved=reserved)
        config_name = f"warp-{input_endpoint}"
        sn_link = Wireguard(serialize_wg=serialize_obj, sn_meta=SnMeta(name=config_name))
        pyperclip.copy(str(sn_link))
        print(f"{'-' * 35} Android 版 NekoBox，WireGuard 的分享SN Link如下: {'-' * 35}\n{sn_link}\n{'-' * 120}")
        print("节点已经复制到剪切板，可以黏贴到其它地方！")
        print(f"{'-' * 120}")
