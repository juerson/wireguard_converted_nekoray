from dataclasses import field, dataclass
import base64
import zlib
import os
import sys
import re
import ast  # 安全解析str成list


# 检查文件是否存在或大小为0，即文件无效
def check_unusable_file(file: str) -> None:
    if not os.path.exists(file) or os.stat(file).st_size == 0:
        sys.exit()


# 读取优选ip的ip.txt文件
def read_txt_endpoints(txt_file: str) -> list[str]:
    endpoints = []
    with open(file=txt_file, mode='r', encoding='utf-8') as rf:
        for line in rf.readlines():
            trim_line = line.strip()
            if trim_line != "":
                endpoints.append(trim_line)
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
    version: int = 2
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
    """ 读取外部文件的数据 """
    files = ["配置文件/wg-config.conf", "ip.txt", "output-node.txt"]
    for file in files[:-1]:
        check_unusable_file(file)  # 检查文件是否存在
    param = read_wg_conf_kv(files[0])
    private_key = param.get("PrivateKey", "+HfkMSyh7obEkX4J8Qa7Xk77CLVn45AW4CdBbnFNaGc=")
    public_key = param.get("PublicKey", "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=")
    reserved = param.get("Reserved", "")
    mtu = param.get("MTU", 1360)
    address_value = param.get("Address", ["172.16.0.2/32"])
    local_address = ",".join(address_value)
    b64 = base64_reserved(str(reserved))

    """ 构建'sn://sg?'的链接 """
    results = []
    endpoints = read_txt_endpoints(files[1])
    for ip_with_port in endpoints:
        try:
            ip = ip_with_port.rsplit(":", 1)[0].strip("[").strip("]")
            port = ip_with_port.rsplit(":", 1)[1]
            serialize_obj = SerializeWG(server=SnServer(ip, int(port)),
                                        localAddress=local_address,
                                        privateKey=private_key,
                                        peerPublicKey=public_key,
                                        mtu=int(mtu), reserved=b64)
            # 配置名称，不能取中文名称，也不能取一些特殊字符，具体支持哪些字符，自己测试
            config_name = f"warp-{ip_with_port}"
            sn_wireguard = Wireguard(serialize_wg=serialize_obj, sn_meta=SnMeta(name=config_name))
            results.append(str(sn_wireguard))
            print(sn_wireguard)
        except Exception as e:
            pass

    """ 将结果写入文件中 """
    if len(results) > 0:
        f = open(files[2], mode='w', encoding='utf-8')
        f.writelines("\n".join(results))
        f.close()
        print(f"已经将节点写入{files[2]}文件中！\n")
        os.system("pause")
