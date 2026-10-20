# aawork

一个使用 Go 编写的 mDNS/TCP 资产发现 CLI。程序保留 mDNS 多播解析（PTR、SRV、TXT、
A 和 AAAA），同时会对 CIDR 中的每个 IPv4/IPv6 主机和指定端口执行受控并发 TCP
扫描；因此没有 mDNS 响应时也能发现开放端口。

## 验证数据集（无需真实设备）

`testdata/` 提供了一套可回放的 mDNS 报文数据集，用于验证 banner 识别深度：

| 文件 | 用途 |
|---|---|
| `testdata/reference-mdns.hex` | 真实 DNS 线上格式报文（十六进制，一行一个报文），由独立 Node.js 实现生成，用于交叉验证 Go 解析器 |
| `testdata/reference-expected.txt` | 该数据集的期望 CLI 输出（golden） |
| `testdata/gen_reference_packet.js` | 报文生成器；修改数据集后运行 `node testdata/gen_reference_packet.js` 重新生成 |

离线回放：

```powershell
go run . -cidr 192.168.1.0/24 -ports 9,445,548,5000 -fixture testdata/reference-mdns.hex
```

输出与 `testdata/reference-expected.txt` 逐字节一致，覆盖 workstation、http、smb、
qdiscover、device-info、afpovertcp 六个服务以及全部深度字段。

## 使用

```powershell
go run . -cidr 192.168.1.0/24 -ports 80,443,5000-5010
```

可选参数：

- `-timeout 3s`：mDNS 等待和 TCP 连接超时
- `-interface "以太网 2"`：只使用指定网卡；名称以 Windows `Get-NetAdapter` 的结果为准
- `-format json`：输出机器可读的 JSON
- `-verbose`：在文本输出中追加 `IP`、`Host`、`probe`、`header.*` 诊断行
- `-scan-timeout 10m`：可选的整轮 TCP 扫描预算；默认 `0` 表示不设全局截止时间

`-timeout` 只约束 mDNS 收集窗口和单条 TCP 连接，不会作为整轮扫描的全局截止时间。
未出现结果时关闭端口会被判定为 `closed`，而不是因全局超时被误判为 `timeout`。

默认文本输出与参考响应格式一致：

```text
services:
9/tcp workstation:
Name=slw-nas [24:5e:be:69:a3:13]
IPv4=192.168.1.10
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
5000/tcp qdiscover:
Name=slw-nas
IPv4=192.168.1.10
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
accessType=https,accessPort=86,model=TS-X64,displayModel=TS-464C,fwVer=5.2.9,fwBuildNum=20260214
device-info:
Name=slw-nas(AFP)
IPv4=192.168.1.10
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
model=Xserve
answers:
PTR:
_workstation._tcp.local
_http._tcp.local
_smb._tcp.local
_qdiscover._tcp.local
_device-info._tcp.local
_afpovertcp._tcp.local
```

规则说明：

- mDNS TXT 只在其所属服务内合并，不会串到其它服务。
- TXT 字段按固定顺序合并为一行，MAC 已并入 `Name` 时不再重复输出。
- 无端口的 mDNS 服务（如 `device-info`）输出为 `device-info:`，不带端口前缀。
- 服务顺序固定为 workstation、http、smb、qdiscover、device-info、afpovertcp。

JSON 输出包含 `ip`、`port`、`host`、`hostname`、`service`、`banner`、`mac`、
`txt`，以及 `probe`（协议、状态、响应头）。

扫描规模遵循常规主机语义：IPv4 子网会跳过网络地址和广播地址（/31、/32 除外），
IPv6 会跳过子网标识地址。主机/端口组合采用流式生成，不会一次性物化到内存，
因此 `/24` × `1-10000`（254 万目标）可以正常执行。仅主机总数有上限（65536），
端口连接并发固定限制为 128，单个连接受 `-timeout` 限制，整轮可用 `-scan-timeout` 约束。
mDNS 只能在可达的本地链路多播域中发现服务，因此跨三层网段通常不会收到响应；
TCP 扫描不依赖 mDNS。

## mDNS 端口占用处理

系统自带的 mDNS 守护进程（macOS Bonjour、Linux Avahi、Windows Dnscache）通常独占
UDP 5353。程序优先在 5353 上加入多播组；若绑定失败（权限被拒或地址已占用），
会自动回退为「临时端口 + QU 单播应答位」模式：查询仍发往 `224.0.0.251:5353`，
但要求应答方直接单播回包到本程序的临时端口，因此不会与系统守护进程争抢 5353。

回退模式下无法监听其他主机主动发送的多播通告，只能看到对本次查询的应答。

## Run

```powershell
go run . -cidr 192.168.1.0/24 -ports 80-8080
```
