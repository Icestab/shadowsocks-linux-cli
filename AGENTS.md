# AGENTS.md

sscli：Go 实现的 Linux TUN 全局代理客户端（Shadowsocks DIRECT/PROXY 分流）。
架构：`wireguard-go TUN → gvisor netstack（用户态 TCP/IP 栈）→ router（分流决策）→ DIRECT=原生带 fwmark socket / PROXY=sslocal(SOCKS5) 子进程`。
Shadowsocks 加密协议完全由 shadowsocks-rust 的预编译 `sslocal` 子进程承担，本项目不实现任何加密。

## 构建与测试（必须遵守）

```bash
source scripts/env.sh   # 必须：GOPATH/GOCACHE/GOMODCACHE 重定向到 .toolchain，别污染系统 Go 缓存
go build ./...
go vet ./...
go test ./internal/... -count=1        # 改完必跑全量
go test -race ./internal/tun/ ./internal/dns/ ./internal/daemon/   # 并发敏感包
```

环境事实：开发沙箱**无 sudo/root**。需要 root 的验证（`sscli start/stop`、iptables、ip rule）由用户手动执行。测试必须不依赖 root：纯函数 + httptest + 假 DNS 上游 + 直接往 gvisor channel endpoint 注入报文。

## 架构速览（改代码前先读对应文件，注释里有大量"为什么"）

- `cmd/sscli/main.go` —— 入口与 `version` 字符串
- `internal/tun/stack.go` —— TUN↔gvisor 桥。写包必须 `packForWrite`（virtioNetHdrLen=10 头空间+offset，offset=0 会全部失败）；读必须批量化（内核 GSO 超级包，`tun.ErrTooManySegments` 是部分读信号，`continue` 而不是退出）
- `internal/tun/flow.go` —— TCP 流终结（4096 并发准入，超限 `Complete(true)` 回 RST）；UDP DNS 与中继（每流空闲回收）
- `internal/router/router.go` —— 分流决策；服务器**解析出的全部** IP pin 为直连（防 DNS 轮询回环）
- `internal/dns/` —— 分流解析器（直连上游走 TCP）、NODATA 与 NXDOMAIN 语义、域名→IP 映射表
- `internal/network/` —— 策略路由（Setup/Teardown 幂等可逆）、iptables 管理（snapshot-delta + 状态文件，**只准删自己插的规则**）：DNS 劫持 + conntrack 既有连接豁免
- `internal/daemon/runtime.go` —— boot/stop 顺序。铁律：**安全第一**——boot 任一环节失败必须全量回滚，绝不让机器处于断网状态；teardown 幂等；PID 验身（/proc exe）
- `internal/proxy/` —— sslocal 子进程（nobody 降权、密码经 0600 临时配置传给子进程、`StartIP` 防止劫持后自解析死锁）

## 历史踩坑 —— 破坏任一行为都会复现整机断网（保持警惕）

- TUN 写偏移 offset=0 → 内核返回路径全灭 → 看起来"启动就断网"
- gvisor 缺 `SetSpoofing` / promiscuous → 无 SYN-ACK，所有连接卡 SYN-SENT
- `r.Complete(true)` 才给应用发 RST；`false` 只是释放请求
- gvisor **UDP forwarder endpoint 没有 idle 超时**：每个新 5 元组 endpoint+goroutine 会永久存活，所有 UDP 流必须自己回收（`time.AfterFunc` 关 conn）+ `Stack.Close` 统一关闭
- gvisor **TCP forwarder 只接受 SYN**：既有连接应答/入向连接 SYN-ACK 被吞 → 靠 iptables `mangle OUTPUT` 的 conntrack ESTABLISHED/RELATED mark 豁免（**仅限 TCP**——UDP 豁免会让长连接 DNS socket 绕过劫持、饿死域名映射表）
- DNS：空答案是 **NODATA（NOERROR）**，只有上游 NXDOMAIN 才算 NXDOMAIN；把 AAAA 无记录当 NXDOMAIN 是用户踩过的 bug
- 服务器域名启动解析：先 DoH（RFC 8484 GET，回退 alidns→cloudflare）再系统 DNS，回退要告警——别改回纯系统解析（隐私泄漏）

## 变更与发布规范

- 提交信息：`fix|feat|docs|chore(模块): 中文一行标题`，body 解释**为什么**（本项目注释与提交都重"为什么"轻"是什么"，且注释是文档，不要删）
- 每个修复配回归测试；改行为先跑全量测试再提交
- 版本号：`cmd/sscli/main.go` 的 `version`（如 v0.2.4）。**不要手动跑 `scripts/package.sh`**
- 发布流程：推 master + 推 annotated tag `v<major.minor.patch>` → GitHub Actions `release.yml` 自动打包发布 Release
- 新增用户可见行为时，README.md 与 README_EN.md 同步更新