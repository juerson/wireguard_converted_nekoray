from dataclasses import field, dataclass
import base64
import zlib
import os
import sys


# 检查文件是否存在或大小为0，即文件无效
def check_file_exist_or_zero_size(file):
    if not os.path.exists(file) or os.stat(file).st_size == 0:
        sys.exit()


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
        print(endpoints)
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
                if line.startswith("Reserved"):
                    wireguard_param["Reserved"] = line.strip().replace(' ', '').replace("Reserved=", '')
        return wireguard_param


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
class WireguardSerialize(SnBase):
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
    WireguardSerialize: WireguardSerialize = field(default_factory=WireguardSerialize)
    sn_meta: SnMeta = field(default_factory=SnMeta)

    def __str__(self) -> str:
        # print(self.serialize())
        return f'sn://wg?{base64.urlsafe_b64encode(zlib.compress(self.serialize())).decode()}'


if __name__ == '__main__':
    """ 读取外部文件的数据 """
    files = ["配置文件/wg-config.conf", "result.csv"]
    for file in files:
        check_file_exist_or_zero_size(file)  # 检查文件是否存在
    param = read_wireguard_key_parameters(files[0])
    private_key = param.get("PrivateKey")
    private_key = private_key if private_key else "+HfkMSyh7obEkX4J8Qa7Xk77CLVn45AW4CdBbnFNaGc="  # 找不到就使用这个私钥
    public_key = param.get("PublicKey")
    public_key = public_key if public_key else "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="  # 找不到就使用这个公钥
    Reserved = param.get("Reserved")
    Reserved = Reserved if Reserved else ""  # 找不到，就用空字符代替
    mtu = param.get("MTU")
    mtu = int(mtu) if mtu else 1280  # 找不到，就使用1280代替
    Address = param.get("Address")
    if Address is None or Address == "":
        local_address = "172.16.0.2/32"
    else:
        local_address = ",".join(Address) if isinstance(Address, list) else "172.16.0.2/32"

    """ 构建'sn://sg?'的链接 """
    results = []
    endpoints = read_ip_endpoints(files[1])
    for ip_with_port in endpoints:
        try:
            ip = ip_with_port.rsplit(":", 1)[0].strip("[").strip("]")
            port = ip_with_port.rsplit(":", 1)[1]
            serialize_obj = WireguardSerialize(server=SnServer(ip, int(port)),
                                               localAddress=local_address,
                                               privateKey=private_key,
                                               peerPublicKey=public_key,
                                               mtu=int(mtu), reserved=Reserved)
            # 配置名称，不能取中文名称，也不能取一些特殊字符，具体支持哪些字符，自己测试
            config_name = f"warp-{ip_with_port}"
            sn_wireguard = Wireguard(WireguardSerialize=serialize_obj, sn_meta=SnMeta(name=config_name))
            results.append(str(sn_wireguard))
            print(sn_wireguard)
        except Exception as e:
            pass

    """ 将结果写入文件中 """
    if len(results) > 0:
        output_file = 'output_node.txt'
        f = open(output_file, mode='w', encoding='utf-8')
        f.writelines("\n".join(results))
        f.close()
        print(f"已经将节点写入{output_file}文件中！\n")
        os.system("pause")
