# mDNS-go

一个使用 Go 编写的 mDNS/TCP 资产发现 CLI。程序保留 mDNS 多播解析（PTR、SRV、TXT、
A 和 AAAA），同时会对 CIDR 中的每个 IPv4/IPv6 主机和指定端口执行受控并发 TCP
扫描；因此没有 mDNS 响应时也能发现开放端口。

## 项目结构

代码按职责分层：`cmd/` 只做进程装配，`internal/` 每个包只承担一个关注点，
依赖方向单向：`discovery` 依赖 `mdns`、`scan`、`model`；`render` 只依赖 `model`；
`cli`、`mdns`、`model` 不依赖其他内部包。

| 路径 | 职责 |
|---|---|
| `cmd/mdns-go/main.go` | 进程入口：解析参数、映射退出码、选择实时扫描或数据集回放 |
| `internal/cli` | `Options`、flag 注册与校验、端口区间解析、退出码映射 |
| `internal/model` | 领域类型（`Asset`、`ProbeResult`、`TLSInfo`、`ScanOutput`）、排序规则、MAC 归一化 |
| `internal/mdns` | DNS 报文编解码、服务名语义、接口级查询套接字与 5353 占用回退、报文数据集加载 |
| `internal/scan` | 主机枚举与规模校验、并发探测池、TCP/TLS/HTTP/SMB 探测、端口到协议映射 |
| `internal/discovery` | 发现主流程：网卡选择、mDNS 窗口、mDNS 结果组装为资产、TCP 扫描编排 |
| `internal/render` | 文本输出渲染与 TXT 可见性规则 |
| `testdata/` | 可回放的 mDNS 报文数据集与 golden 输出 |

测试文件与被测包同目录；`testdata/` 保留在仓库根目录，因此 `internal/discovery`
的测试通过 `../../testdata` 引用数据集，CLI 与 Docker 回放仍使用仓库根目录的相对路径。

## 验证数据集（无需真实设备）

`testdata/` 提供了一套可回放的 mDNS 报文数据集，用于验证 banner 识别深度：

| 文件 | 用途 |
|---|---|
| `testdata/reference-mdns.hex` | 真实 DNS 线上格式报文（十六进制，一行一个报文），由独立 Node.js 实现生成，用于交叉验证 Go 解析器 |
| `testdata/reference-expected.txt` | 该数据集的期望 CLI 输出（golden） |
| `testdata/gen_reference_packet.js` | 报文生成器；修改数据集后运行 `node testdata/gen_reference_packet.js` 重新生成 |

离线回放：

```powershell
go run ./cmd/mdns-go -cidr 192.168.1.0/24 -ports 9,445,548,5000 -fixture testdata/reference-mdns.hex
```

输出与 `testdata/reference-expected.txt` 逐字节一致，覆盖 workstation、http、smb、
qdiscover、device-info、afpovertcp 六个服务以及全部深度字段。

## 使用

```powershell
go run ./cmd/mdns-go -cidr 192.168.1.0/24 -ports 80,443,5000-5010
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

## 本地运行

```powershell
go run ./cmd/mdns-go -cidr 192.168.1.0/24 -ports 80-8080
```

## Docker 部署

镜像为多阶段构建，产物约 13 MB，运行阶段基于 `alpine`，以非 root 用户（UID 10001）
运行，无 shell、无包管理器依赖。

### 构建

```powershell
docker build -t mdns-go:local .
```

### 运行（单次扫描）

```powershell
docker run --rm --network host mdns-go:local `
  -cidr 192.168.1.0/24 `
  -ports 80,443,445,548,5000 `
  -timeout 2s
```

### 使用 Docker Compose

```powershell
$env:CIDR  = '192.168.1.0/24'
$env:PORTS = '1-1024'
docker compose run --rm mdns-go
```

可用环境变量：

| 变量 | 默认值 | 说明 |
|---|---|---|
| `CIDR` | `192.168.1.0/24` | 目标网段 |
| `PORTS` | `1-1024` | 端口或端口范围 |
| `TIMEOUT` | `2s` | mDNS 窗口与单连接超时 |
| `SCAN_TIMEOUT` | `0s` | 整轮扫描预算，`0` 表示不限 |
| `FORMAT` | `text` | `text` 或 `json` |

### 容器内离线验证数据集

```powershell
docker compose --profile replay run --rm replay
```

或直接挂载目录：

```powershell
docker run --rm -v "${PWD}:/data:ro" mdns-go:local `
  -cidr 192.168.1.0/24 -ports 9,445,548,5000 `
  -fixture /data/testdata/reference-mdns.hex
```

### 网络说明（重要）

mDNS 依赖二层多播，必须使用 `--network host`（或 `network_mode: host`）：

- **Linux 主机**：`host` 网络直接使用宿主机网卡，mDNS 与 TCP 扫描均正常。
- **Docker Desktop（Windows / macOS）**：`host` 网络指向的是 Docker 的 Linux 虚拟机，
  不是物理网卡。TCP 扫描仍可通过 NAT 访问局域网（已验证可发现宿主机端口并抓取
  banner），但 **mDNS 多播收不到局域网应答**，此时应改用数据集回放，或把程序直接
  跑在宿主机上。默认 `bridge` 网络下同样收不到 mDNS。

容器不需要 `NET_ADMIN` 或 `NET_RAW`，也不需要 root：多播加入和大于 1024 的端口绑定
在普通用户下即可完成。Compose 文件已启用 `read_only`、`cap_drop: [ALL]` 与
`no-new-privileges`。
