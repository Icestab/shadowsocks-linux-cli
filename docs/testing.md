# 测试指南

## 单元测试（无需 root）

```bash
. scripts/env.sh && go test ./...
```

| 包 | 覆盖内容 |
|---|---|
| `internal/rules` | 域名精确/后缀匹配（含 notexample.com 反例）、CIDR 最长前缀、三模式验收矩阵、自定义规则优先级、GFW List base64 解析、dnsmasq 格式解析、9.5万条规则性能（<0.1s/40万次查询） |
| `internal/config` | 加载/校验/默认值/非法模式拒绝/mode 原子改写保留其他键 |
| `internal/dns` | 域名→IP 映射（CDN 多对一、TTL 过期）、DNS 应答、上游超时上限 |
| `internal/router` | IP 连接经映射表还原域名后正确分流、DIRECT/PROXY 路径选择 |
| `internal/proxy` | **SS 全链路端到端**：本地 ssserver + 托管 sslocal + ProxyDialer 回环 HTTP 请求 |
| `internal/network` | 只读辅助函数（不改动宿主路由） |

## 非特权功能验证

```bash
go build -o bin/sscli ./cmd/sscli
./bin/sscli config init
# 编辑 config.yaml 填入真实服务器信息
./bin/sscli update          # 下载真实规则
./bin/sscli route github.com baidu.com google.com 192.168.1.1 8.8.8.8
./bin/sscli test
```

## root 级端到端测试（WSL2 / Linux）

```bash
sudo SSCLI=/path/to/bin/sscli ./scripts/e2e-test.sh
```

流程：启动 → 校验 TUN/fwmark 规则/独立路由表 → 直连可用性 → 停止 → 校验 TUN 删除、ip rule 清空、默认路由恢复、外网可达。

脚本带 `trap cleanup EXIT`，任何一步失败都会执行清扫，不会把系统留在断网状态。

### WSL2 注意事项

- 确认内核支持 TUN：`ls -l /dev/net/tun`
- 建议 NAT 网络模式（`/etc/wsl.conf` 中未开启 mirrored networking）
- 测试期间 Windows 宿主机网络不受影响；测试只改 WSL 内部命名空间

## 手动验证清单（对应需求三十四）

- [ ] gfw 模式：baidu DIRECT / github PROXY / google PROXY / 192.168.1.1 DIRECT / 10.0.0.1 DIRECT
- [ ] bypass 模式：baidu DIRECT / 国外 IP PROXY / 局域网 DIRECT
- [ ] global 模式：baidu PROXY / 中国 IP PROXY / 局域网 DIRECT
- [ ] curl/git/npm 不设代理环境变量直接可用
- [ ] sudo sscli stop 后 TUN 删除、路由恢复、ip rule 恢复、网络正常
