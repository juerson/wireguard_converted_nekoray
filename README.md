# wireguard_converted_nekoray

该项目库主要功能是：将 Cloudfare WARP 密钥生成的 WireGuard 配置文件转换为 NekoBox 的 nekoray 节点，支持生成单个 nekoray 节点、批量生成 nekoray 节点。
批量生成 nekoray 节点所导入的数据，支持优选WARP IP地址程序的result.csv文件，也支持一行一个“ip:port“的ip.txt文件。

## 1、使用截图

<img src="https://github.com/juerson/wireguard_converted_nekoray/assets/37030166/02d25cdf-d703-48a7-a3f2-a6a4cbdfb6b9" alt="生成单个节点" />

<img src="https://github.com/juerson/wireguard_converted_nekoray/assets/37030166/59aa507e-64f5-458c-b644-124721397e60" alt="生成批量节点" />

<img src="https://github.com/juerson/wireguard_converted_nekoray/assets/37030166/310aed07-a59f-4517-b340-b3d26b55a4a0" alt="导入NekoBox代理软件中" />

<img src="images\ipv4_nodes.png" />

<img src="images\ipv6_nodes.png" />

注意：您家的宽带或光纤网络没有IPv6地址的，无法跑出IPv6的[result.csv](https://github.com/MiSaturo/CFWarp-Windows)文件，不管您从网上哪些弄来reult.csv文件(包括这个代码库)，没有IPv6的地址，是使用不了的，除非套一层IPv6的代理。本代码中的IPv6 UDP延迟测试，也是基础cf warp的ipv6地址测试出来的。

## 2、文件解压后，需要注意的事项：

- 1、在“配置文件“的目录下，改成自己的 WireGuard 的配置信息，因为它是普通账号的 conf 配置信息，流量和使用设备有限制，大家都不修改它，使用的人数多，可能导致生成的 nekoray 节点无法使用。特别要注意的是，Address 这个参数的IPv4和IPv6地址必须写在一行中，而且用逗号隔开，有的本地软件或网上生成的 conf 配置文件是写成两行 Address 的，要改成一行的。
- 2、ip.txt 和 result.csv 这两个文件为批量生成 nekoray 节点时，需要用到的，格式就这样。毕竟批量生成 nekoray 节点需要对应的优选ip数据，这两个文件必须，而且不能改为其它名字，打包成的exe程序已经写死了，想要其他名字，自己修改源代码，再打包成自己的程序。
- 3、ip.txt 文件对应 “使用方式2_批量写入nekoray节点（txt文件）.exe” 这个程序，result.csv 文件 对应 “使用方式3_批量写入nekoray节点（csv文件）.exe” 这个程序，捆绑使用的，缺失不能正常使用exe程序的。
- 4、我发现 wg-config.conf 中的 MTU 参数设置不同的值，可能会影响网速快或慢，以及节点是否能正常使用，故在程序中，也添加是否手动修改 nekoray 节点参数中 MTU 值的功能，如果没有输入任何东西就按回车键，就默认使用 wg-config.conf  文件中的 MTU 值。MTU值的设置可以参考：[wireguard_peer_mtu.csv](https://gist.github.com/nitred/f16850ca48c48c79bf422e90ee5b9d95) 里面的表格的数据尝试修改。

## 3、使用到的工具：

NekoBox Windows版：https://github.com/MatsuriDayo/nekoray/releases
