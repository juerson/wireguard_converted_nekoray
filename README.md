# wireguard_converted_nekoray

该代码库主要用途：将 Cloudfare WARP 密钥生成的 WireGuard 配置文件转换为 NekoBox 的 nekoray 节点，支持生成单个 nekoray 节点、批量生成 nekoray 节点。
批量生成 nekoray 节点所导入的数据，支持WARP优选IP程序输出的result.csv文件（具体格式，使用过的人都知道的），也支持一行一个“ip:port“的ip.txt文件。

## 1、使用截图

<img src="images\Screenshot.png" />

<img src="images\nekoray_links.png" />

<img src="images\ipv4_warp.png" />

<img src="images\ipv6_wrap.png" />

<img src="images\wireguard.png" />

注意：有线宽带或光纤、无线WiFi没有公网 IPv6 地址的，无法跑出IPv6的 [result.csv](https://github.com/MiSaturo/CFWarp-Windows) 文件，不管您从网上哪些弄来reult.csv文件(包括这个代码库)，没有IPv6的地址，是使用不了的，除非套一层IPv6的代理。本代码中的IPv6 UDP延迟测试，是基于 Cloudflare WARP 提供的 IPv6 地址测试出来的。

**【新增加】**支持其他服务商提供的 wireguard 配置文件，由于没有大量、不同服务商提供的 WireGuard 配置文件作为数据测试，不保证所有WireGuard 配置文件转为nekoray 链接都能使用，建议自己测试。目前我只知道用到如图所示的 PrivateKey、Address 、PublicKey 、Endpoint 四个参数的值就能使用：

<img src="images\支持其他服务商提供的WireGuard配置文件.png" />

## 2、文件解压后，需要注意的事项：

- 1、在 "配置文件" 目录下，改成自己的 WireGuard 的配置信息（将整个 wg-config.conf 文件替换成自己的），防止生成的 nekoray 节点使用网速为龟速，甚至无法使用。特别要注意的是，Address 这个参数的 IPv4 和 IPv6 地址必须写在一行中，而且用逗号隔开，有的本地软件或网上生成的 wg-config.conf  配置文件是写成两行 Address 的，建议改成一行的，当然也可以修改代码。
- 2、ip.txt 和 result.csv 这两个文件为批量生成 nekoray 节点时，需要用到的，格式就这样。毕竟批量生成 nekoray 节点需要对应的优选IP数据，这两个文件必须，而且不能改为其它名字，打包成的exe程序已经写死了，想要其他名字，自己修改源代码，再打包成自己的程序。
- 3、ip.txt 文件对应 "2.批量写入nekoray节点（txt文件）.exe"这个程序，result.csv 文件 对应"3.批量写入nekoray节点（csv文件）.exe"这个程序，当然还有"配置文件/wg-config.conf"这个文件也是捆绑使用的，缺失不能正常使用exe程序的。
- 4、我发现 wg-config.conf 中的 MTU 参数设置不同的值，可能会影响网速快和慢，以及节点是否能正常使用，故在程序中，也添加是否手动修改 nekoray 节点参数中 MTU 值的功能（当然也可以在 wg-config.conf  配置文件中修改），exe程序运行过程中，提示要修改MTU值的，如果没有输入任何东西就按 Enter 回车键，就默认使用 wg-config.conf  配置文件中的 MTU 值，wg-config.conf 配置文件中，没有 MTU 这项参数就使用 1408。MTU值的设置可以参考：[wireguard_peer_mtu.csv](https://gist.github.com/nitred/f16850ca48c48c79bf422e90ee5b9d95) 里面的表格的数据尝试修改。

## 3、使用到的工具：

NekoBox Windows版：https://github.com/MatsuriDayo/nekoray/releases
