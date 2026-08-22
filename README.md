# sscli — Linux 原生 CLI Shadowsocks 分流客户端

中文 | [English](README_EN.md)

一个轻量、原生 Linux、无 GUI 的 Shadowsocks 分流工具。通过 Linux TUN 接管系统流量，根据 GFW List、中国域名/中国 IP 列表、局域网规则进行 DIRECT / PROXY 分流。

```text
Linux / WSL
     │  所有应用流量（无需设置任何代理环境变量）
     ▼
   TUN 网卡 (sscli0)
     │
     ▼
 sscli 路由引擎（gvisor 用户态 TCP/IP 栈 + 规则匹配）
     │
     ├──── DIRECT ──→ 直接出网（fwmark 防回环）
     │
     └──── PROXY ───→ 本地 SOCKS5 → sslocal → VPS
```

**Shadowsocks 协议完全复用 [shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust) 的预编译 `sslocal` 二进制（托管子进程），sscli 不自行实现任何加密协议。**

## 特性

- **三种模式**：`gfw`（默认，仅代理 GFW List 命中目标）、`bypass`（默认代理，绕过中国）、`global`（除局域网全代理）
- **TUN 接管**：基于 gvisor netstack（sing-box/mihomo 同款用户态 TCP/IP 栈）
- **防代理死循环**：fwmark + 独立路由表 + VPS /32 主机路由豁免三重防护
- **DNS 分流**：内置分流解析器（中国域名走国内上游），域名→IP 映射表支撑基于域名的 IP 连接路由；架构预留 DoH/DoT/Fake-IP 扩展点
- **规则系统**：GFW List / 中国域名 / 中国 IP / 自定义规则，优先级明确，Hash+基数树结构支撑数十万条目毫秒级匹配
- **安全退出**：SIGINT/SIGTERM/SIGHUP 全量恢复网络状态，崩溃后可用 `sscli stop` 清扫残留
- **IPv6 防泄漏**：默认 `ipv6.block: true`，避免 IPv6 流量绕过代理

## 安装

### 方式一：下载发布包（推荐，无需 Go 环境）

从 [GitHub Releases](https://github.com/Icestab/shadowsocks-linux-cli/releases) 下载对应架构的 `sscli-v<版本>-linux-<架构>.tar.xz`（附 `.sha256` 校验文件）。

**包内自带全部依赖**：静态编译的 sscli、官方预编译 sslocal、打包时点的三份路由规则基线——安装阶段无需联网，也没有"没有代理就下不了规则"的引导问题：

```bash
echo "<官方sha256>  sscli-v0.1.1-linux-x86_64.tar.xz" | sha256sum -c -   # 可选校验
tar xJf sscli-v0.1.1-linux-x86_64.tar.xz && cd sscli-v0.1.1-linux-x86_64
sudo ./install.sh     # 离线完成部署，随后自动尝试在线刷新规则到最新
```

### 方式二：源码一键安装

```bash
./scripts/install.sh
```

脚本自动完成：构建 sscli → 下载官方预编译 sslocal（SHA256 校验）→ 安装二进制 → 生成 `/etc/sscli/config.yaml` 配置模板（0600）→ 下载分流规则 → 运行自检。装完只需编辑配置里的服务器信息即可 `sudo sscli start`。

用户级安装（不需要 root）：`PREFIX=~/.local ./scripts/install.sh`

### 手动安装

#### 1. 构建

```bash
git clone <repo> && cd shadowsocks-linux-cli
./scripts/install.sh          # 构建并安装到 /usr/local/bin
# 或仅构建：
go build -o bin/sscli ./cmd/sscli
```

依赖：Go 1.22+，iproute2（`ip` 命令）。

### 2. 安装 sslocal（预编译，无需自己编译）

一键脚本会自动完成此步；手动方式：

```bash
curl -sL https://github.com/shadowsocks/shadowsocks-rust/releases/latest/download/<对应平台包>.tar.xz \
  | tar xJ -C /tmp sslocal
sudo install -m755 /tmp/sslocal /usr/local/bin/sslocal
```

### 3. 配置

```bash
sudo sscli config init        # 或直接编辑 /etc/sscli/config.yaml
sudoedit /etc/sscli/config.yaml
```

最小配置示例：

```yaml
mode: gfw            # gfw | bypass | global

server:
  address: your.server.com
  port: 443
  method: aes-256-gcm
  password: "your-password"

tun:
  name: sscli0
  mtu: 1500
  address: 198.18.0.1/15

sslocal:
  binary_path: /usr/local/bin/sslocal
  socks_addr: 127.0.0.1:1080

rules:
  - domain: github.com
    action: proxy
  - domain_suffix: corp.internal
    action: direct
```

配置文件含密码，权限保持 `0600`。

## 使用

```bash
sudo sscli start              # 启动（需要 root/CAP_NET_ADMIN）
sscli status                  # 查看运行状态
sscli mode bypass             # 切换模式（重启生效）
sscli route github.com baidu.com   # 查询目标的分流决策
sscli dns google.com          # 测试 DNS 解析与分流
sscli test                    # 自检（权限/TUN/DNS/SS链路/规则）
sscli update                  # 更新 GFW List / 中国域名 / 中国 IP 规则
sudo sscli stop               # 停止并恢复网络
```

### 权限说明

只有 `start`/`stop`/`restart` 需要 root（TUN 与策略路由是 `CAP_NET_ADMIN` 特权操作）。`mode`、`route`、`dns`、`update`、`test`、`status`、`config` 均可普通用户执行。

## 规则优先级

```text
1. Private/LAN      （系统保留，所有模式直连）
2. 用户自定义规则
3. 中国域名          （gfw/bypass 生效）
4. 中国 IP           （gfw/bypass 生效）
5. GFW List
6. 当前模式默认行为   （gfw→DIRECT，bypass/global→PROXY）
```

规则文件位于 `~/.config/sscli/rules/`（或 `/etc/sscli/rules/`），由 `sscli update` 维护，支持断点安全的原子替换——下载或校验失败不会破坏现有规则。

## 开发与测试

```bash
go test ./...                 # 单元测试（规则引擎/DNS/SS链路/路由决策）
./scripts/e2e-test.sh         # root 级端到端测试（需 sudo，见下）
```

端到端测试覆盖需求验收标准：启动后 TUN/策略路由就位、直连不被破坏、停止后 TUN/路由/ip rule 完整恢复且网络可用。

详见 [docs/testing.md](docs/testing.md)。

## 当前状态

### 已实现

- CLI 全命令集：`start/stop/restart/status/test/update/mode/rules/route/dns/config`
- 配置加载/校验/模式热切换（原子改写 YAML）
- Shadowsocks 链路：托管 sslocal 子进程（密码经 0600 临时配置文件传递，不进命令行），SOCKS5 出站，本地 ssserver 回环端到端测试通过
- TUN + gvisor netstack TCP 流终结，DNS(UDP 53) 劫持应答，其余 UDP 预留
- 策略路由：fwmark 逃逸、14 个私有网段豁免、VPS 主机路由、独立表默认路由，全部操作可逆
- DNS 分流解析器 + TTL 域名映射表
- 三种模式（真实规则数据验证符合验收矩阵）
- 规则下载/校验/原子替换
- 信号处理与网络状态恢复：SIGINT/SIGTERM/SIGHUP 全量清理，`sscli stop` 幂等可清扫崩溃残留（不依赖 systemd，手动管理为唯一方式）

### 未实现（第一阶段明确不做）

- UDP 完整转发（入口已预留：非 53 端口 UDP 目前丢弃）
- Fake-IP、DoH/DoT（DNS 模块接口已预留）
- IPv6 完整代理（默认阻断防泄漏，架构已预留 v6 CIDR 匹配）
- GUI/Web UI/Clash API/订阅/多节点等（见需求三十二）

### 已知限制

- WSL2 mirrored 网络模式下策略路由可能与宿主共享栈冲突，建议 NAT 模式使用
- 崩溃（kill -9）后的残留清扫需手动执行一次 `sudo sscli stop`

## 许可

本项目代码采用 MIT；gvisor(Apache-2.0)、wireguard/tun(MIT)、miekg/dns(BSD-3)、x/net(BSD-3) 均为宽松许可；shadowsocks-rust 以外部二进制方式使用（MIT）。
