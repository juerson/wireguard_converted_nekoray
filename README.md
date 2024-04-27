# wireguard_converted_nekoray

该代码库主要用途：使用 Cloudfare WARP 密钥生成的 WireGuard 配置文件的参数，转换为 NekoBox 客户端的 `nekoray://` 或 `sn://` 分享链接、转换为 Clash 配置文件。

- 单个转换：按照程序傻瓜式操作，输入 WARP 的优选 IP ，生成对应的 `nekoray://` 或 `sn://` 分享链接（生成的链接，已经复制到剪切板）。

- 批量转换：支持 `ip.txt` 文件(每行一个 `IP:PORT` 格式的 WARP 优选 IP )、`result.csv` 文件的数据输入，批量转换。

  （1）生成对应的 `nekoray://` 或 `sn://`分享链接，输出到 `output-node.txt` 文件中。

  （2）转换为 clash 配置文件，使用最简单的方法，字符串替换大法，将 `配置文件/clash.yaml`中的clash模板中，需要替换的字符替换掉，模板文件中的内容均来自 [subconverter v0.9.0](https://github.com/tindy2013/subconverter) 程序转换而来的，没有任何删改，除了添加 `dns` 相关的字段外。

### 一、使用注意

1、建议使用前，将 `配置文件/wg-config.conf` 文件中的参数，改为自己的。

2、`Reserved` 参数的值，我暂时没有发现有什么作用，添加和不添加 `Reserved` 值都能使用。

3、想填写 `Reserved` 参数的值，不知道这个 `Reserved` 值怎么来的？之前听说过数组类型的 `Reserve`（例如：`[173,177,149]`），但是又听说 Android 版的 `NekoBox` 的 `Reserved` 只支持字符串类型的 `Reserve` (4个字符)？该怎么获取字符串类型的 `Reserve` ？网上找了一下，这个[视频](https://www.youtube.com/watch?v=FBAiyjZhNqk)可能能解答你的问题，介绍了如何将数组类型的 `Reserved` 转换为字符串类型的 `Reserved` （[附：转换平台](https://gchq.github.io/CyberChef/#recipe=From_Decimal('Comma',false)To_Base64('A-Za-z0-9%2B/%3D')&input=MTczLDE3NywxNDk)）。

4、WireGuard 的 SN Link 生成，根据[这里](https://github.com/MatsuriDayo/NekoBoxForAndroid/issues/298#issuecomment-1879656040)的代码修改，目前发现 SN Link 的配置名称不能使用中文、某些特殊字符，一些国家的语言可能也不支持，应该缺少某些功能，但是能使用，编译的 EXE 程序，就不留出可以自定义配置名称的功能。

5、MTU 值修改，参考资料：[link](https://gist.github.com/nitred/f16850ca48c48c79bf422e90ee5b9d95/76c6ed28d476d8a7a2d84f7e36844989f3198864)。

6、转换为 Clash 配置文件的，代码中没有使用到 `Reserved` 值。使用过程出现问题且有精力可以排查一下：账号问题(换成自己的 WARP Plus)、MTU值问题、`配置文件/clash.yaml` 文件中的 `dns` 字段值的问题、优选的 IP 问题、Clash 客户端问题（包括 Clash 内核问题），也可能是下面这块代码出问题，特别是dns解析与其它的dns冲突（网速慢的情况，可能跟它有关），可以将 `remote-dns-resolve` 和 `dns`字段删除。

<details>
<summary>点击展开代码</summary>
<pre><code class="language-json">{
  "name": "warp-001",
  "type": "wireguard",
  "server": "162.159.192.1",
  "port": 2408,
  "ip": "172.16.0.2",
  "ipv6": "",
  "private-key": "",
  "public-key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
  "pre-shared-key": "",
  "reserved": "",
  "udp": true,
  "mtu": 1280,
  "remote-dns-resolve": true,
  "dns": [
    "1.1.1.1",
    "1.0.0.1",
    "2606:4700:4700::1111",
    "2606:4700:4700::1001"
  ]
}
</code></pre>
</details>
### 二、相关截图

<img src="images\Screenshot.png" />

<img src="images\android版NekoBox，wireguard的sn分享链接.png" />

<img src="images\ipv4_warp.png" />

<img src="images\ipv6_wrap.png" />

<img src="images\android版NekoBox，wireguard的sn的使用.png" />

注意：有线宽带或光纤、无线 WiFi 没有公网 IPv6 地址的，无法跑出 IPv6 的 [result.csv](https://github.com/MiSaturo/CFWarp-Windows) 文件，不管您从网上哪里弄来 `reult.csv` 文件(包括这个代码库)，没有 IPv6 的地址，是使用不了的，除非套一层 IPv6 的代理。本代码中的 IPv6 UDP 延迟测试，是基于 Cloudflare WARP 提供的 IPv6 地址测试出来的。

支持其他服务商提供的 WireGuard 配置文件，由于没有大量、不同服务商提供的 WireGuard 配置文件作为数据测试，不保证所有WireGuard 配置文件都能转为`nekoray://` 或 `sn://` 链接使用，建议自己测试。目前我只知道，需要如图中 `PrivateKey`、`Address `、`PublicKey`、`Endpoint` 这四个参数值，就能转换/生成 `nekoray://` 或 `sn://` 的分享链接。

<img src="images\支持其他服务商提供的WireGuard配置文件.png" />

<img src="images\wireguard.png" />


### 三、使用到的工具：

- NekoBox Windows版：https://github.com/MatsuriDayo/nekoray/releases
- NekoBox Android版：https://github.com/MatsuriDayo/NekoBoxForAndroid