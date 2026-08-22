#!/usr/bin/env bash
# sscli 数据面诊断脚本 v2 —— 针对第一轮结果的深挖版。
set -u
hdr() { echo; echo "======== $1 ========"; }

SSCLI=${SSCLI:-/usr/local/bin/sscli}
SERVER_IP=$(grep 'address:' /etc/sscli/config.yaml | head -1 | awk '{print $2}')

cleanup() {
    hdr "CLEANUP"
    "$SSCLI" stop >/dev/null 2>&1; "$SSCLI" stop >/dev/null 2>&1
}
trap cleanup EXIT

hdr "0. 配置与基线"
echo "-- server.address: $SERVER_IP"
echo "-- nameserver: $(grep nameserver /etc/resolv.conf | awk '{print $2}')"
rm -f /tmp/diag-fg.log

hdr "1. 前台调试启动"
SSCLI_DEBUG=1 "$SSCLI" start --foreground > /tmp/diag-fg.log 2>&1 &
sleep 4
pgrep -x sscli >/dev/null && echo "  [OK] 进程存活" || { echo "  [BAD] 启动失败:"; cat /tmp/diag-fg.log; exit 1; }

hdr "2. 【关键】服务器主机路由豁免是否生效"
echo "-- 解析到的服务器 IP: $SERVER_IP"
ip route get "${SERVER_IP:-18.139.140.0}" 2>&1 | sed 's/^/  /'
echo "  ↑ 若包含 'dev sscli0' 即为回环铁证；应显示 'via ... dev eth0'"
echo "-- 完整 main 表:"
ip route show table main | sed 's/^/  /'

hdr "3. SOCKS5 链路逐层验证"
echo "-- 3a. 本地端口监听:"
ss -tlnp 2>/dev/null | grep 1080 | sed 's/^/  /' || netstat -tlnp 2>/dev/null | grep 1080 | sed 's/^/  /'
echo "-- 3b. SOCKS5 访问 baidu（验证 sslocal 基本功能）:"
curl -sv --socks5-hostname 127.0.0.1:1080 http://www.baidu.com --max-time 10 -o /dev/null 2>&1 | grep -E "Connected|SOCKS|error|timed|refused|HTTP" | head -6 | sed 's/^/  /'
echo "-- 3c. SOCKS5 访问 google:"
curl -s --socks5-hostname 127.0.0.1:1080 https://www.google.com --max-time 12 -o /dev/null -w '  code=%{http_code}\n'
echo "-- 3d. eth0 发包计数（sslocal 是否在向外重试）:"
T1=$(cat /sys/class/net/eth0/statistics/tx_packets); sleep 3; T2=$(cat /sys/class/net/eth0/statistics/tx_packets)
echo "  eth0 tx: $T1 -> $T2 (差值 $((T2-T1)))"

hdr "4. TUN 数据面：直连 baidu"
RX1=$(cat /sys/class/net/sscli0/statistics/rx_packets 2>/dev/null || echo 0)
curl -s http://www.baidu.com --max-time 8 -o /dev/null -w '  code=%{http_code}\n'
RX2=$(cat /sys/class/net/sscli0/statistics/rx_packets 2>/dev/null || echo 0)
echo "  sscli0 rx: $RX1 -> $RX2"

hdr "5. 调试日志（前台模式全部可见）"
tail -30 /tmp/diag-fg.log | sed 's/^/  /'

hdr "6. 清理重复 iptables 残留并显示终态"
for i in 1 2 3 4 5; do
    iptables -t nat -D OUTPUT -m mark --mark 0x162 -j RETURN 2>/dev/null || break
done
iptables -t nat -S OUTPUT | sed 's/^/  /'
