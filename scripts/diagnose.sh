#!/usr/bin/env bash
# sscli 数据面诊断脚本 v2 —— 针对第一轮结果的深挖版。
set -u
hdr() { echo; echo "======== $1 ========"; }

SSCLI=${SSCLI:-/usr/local/bin/sscli}
SERVER_HOST=$(grep 'address:' /etc/sscli/config.yaml | head -1 | awk '{print $2}')
# 在劫持激活前解析主机名（此时系统 DNS 还可用）；iproute2 自己不做 DNS，
# 直接把主机名喂给 `ip route get` 会报 "any valid prefix is expected"。
SERVER_IP=$(getent ahostsv4 "$SERVER_HOST" 2>/dev/null | awk 'NR==1{print $1}')
[ -z "$SERVER_IP" ] && SERVER_IP="$SERVER_HOST"

cleanup() {
    hdr "CLEANUP"
    "$SSCLI" stop >/dev/null 2>&1; "$SSCLI" stop >/dev/null 2>&1
}
trap cleanup EXIT

hdr "0. 配置与基线"
echo "-- server.address: $SERVER_HOST -> ${SERVER_IP:-未解析}"
echo "-- nameserver: $(grep nameserver /etc/resolv.conf | awk '{print $2}')"
rm -f /tmp/diag-fg.log

hdr "1. 前台调试启动"
SSCLI_DEBUG=1 "$SSCLI" start --foreground > /tmp/diag-fg.log 2>&1 &
sleep 4
pgrep -x sscli >/dev/null && echo "  [OK] 进程存活" || { echo "  [BAD] 启动失败:"; cat /tmp/diag-fg.log; exit 1; }

hdr "2. 【关键】服务器主机路由豁免是否生效"
echo "-- 解析到的服务器 IP: ${SERVER_IP:-获取失败}"
ip route get "${SERVER_IP:-18.139.140.0}" 2>&1 | sed 's/^/  /'
echo "  ↑ 若包含 'dev sscli0' 即为回环铁证；应显示 'via ... dev eth0'"
echo "-- 完整 main 表:"
ip route show table main | sed 's/^/  /'

hdr "2b. VPS 直连复测（在劫持激活状态下验证内核/路由/VPS 三件事）"
SRV_IP="${SERVER_IP:-18.139.140.0}"
if [ -n "$SRV_IP" ] && timeout 5 bash -c "echo > /dev/tcp/$SRV_IP/$(grep 'server_port:' /etc/sscli/config.yaml | awk '{print $2}')" 2>/dev/null; then
    echo "  [OK] TCP 直连 $SRV_IP:$(grep 'server_port:' /etc/sscli/config.yaml | awk '{print $2}') 成功 —— 路由+内核+VPS 全部正常"
else
    echo "  [BAD] TCP 直连失败 —— 内核路由或 VPS 异常（host route 已确认存在）"
fi

hdr "3. SOCKS5 链路逐层验证"
echo "-- 3a. 本地端口监听:"
ss -tlnp 2>/dev/null | grep 1080 | sed 's/^/  /' || netstat -tlnp 2>/dev/null | grep 1080 | sed 's/^/  /'
echo "-- 3b. SOCKS5 访问 baidu（实时采样 sslocal 的 socket 状态）:"
( for i in $(seq 1 20); do
    ss -tnp 2>/dev/null | grep -E "1080|sslocal" | awk '{print "  socket["$i"]:", $1, $5, $6}' | head -3
    sleep 0.5
  done ) > /tmp/diag-socks-sockets.txt &
SAMP=$!
curl -sv --socks5-hostname 127.0.0.1:1080 http://www.baidu.com --max-time 10 -o /dev/null 2>&1 | grep -E "Connected|SOCKS|error|timed|refused|HTTP" | head -6 | sed 's/^/  /'
wait $SAMP 2>/dev/null
echo "  --- 采样到的 sslocal 连接状态(去重):"
sort -u /tmp/diag-socks-sockets.txt | head -8
echo "-- 3c. SOCKS5 访问 google:"
curl -s --socks5-hostname 127.0.0.1:1080 https://www.google.com --max-time 12 -o /dev/null -w '  code=%{http_code}\n'
echo "-- 3d. 测试全程 eth0 发包增量:"
T1=$(cat /sys/class/net/eth0/statistics/tx_packets); sleep 2; T2=$(cat /sys/class/net/eth0/statistics/tx_packets)
echo "  eth0 tx: $T1 -> $T2 (差值 $((T2-T1)))"

hdr "3e. 内置解析器直测（绕过劫持，验证解析器本身）"
dig @127.0.0.1 -p 53090 www.baidu.com A +time=5 +tries=1 2>&1 | grep -E "status|ANSWER|SERVER|timed" | sed 's/^/  /' || echo "  dig 不可用或失败"

hdr "3f. 内置解析器直测国外域名"
dig @127.0.0.1 -p 53090 www.google.com A +time=10 +tries=1 2>&1 | grep -E "status|ANSWER|timed" | sed 's/^/  /'

hdr "4. TUN 数据面：直连 baidu"
echo "-- 4a. 先用 --resolve 跳过 DNS，纯测 TUN->DIRECT 数据面:"
BAIDU_IP=$(dig @223.5.5.5 www.baidu.com +short +time=3 | head -1)
[ -z "$BAIDU_IP" ] && BAIDU_IP=$(dig @114.114.114.114 www.baidu.com +short +time=3 | head -1)
echo "  使用 IP: ${BAIDU_IP:-获取失败}"
if [ -n "$BAIDU_IP" ]; then
    curl -s http://www.baidu.com --resolve "www.baidu.com:80:$BAIDU_IP" --max-time 8 -o /dev/null -w '  code=%{http_code}\n'
fi
RX1=$(cat /sys/class/net/sscli0/statistics/rx_packets 2>/dev/null || echo 0)
TX1=$(cat /sys/class/net/sscli0/statistics/tx_packets 2>/dev/null || echo 0)
curl -s http://www.baidu.com --max-time 8 -o /dev/null
RX2=$(cat /sys/class/net/sscli0/statistics/rx_packets 2>/dev/null || echo 0)
TX2=$(cat /sys/class/net/sscli0/statistics/tx_packets 2>/dev/null || echo 0)
echo "  sscli0 计数: rx $RX1->$RX2 | tx $TX1->$TX2"
echo "  (rx=sscli发往内核的回程包; tx=应用发进sscli的出向包)"
RX1=$(cat /sys/class/net/sscli0/statistics/rx_packets 2>/dev/null || echo 0)
curl -s http://www.baidu.com --max-time 8 -o /dev/null -w '  code=%{http_code}\n'
RX2=$(cat /sys/class/net/sscli0/statistics/rx_packets 2>/dev/null || echo 0)
echo "  sscli0 rx: $RX1 -> $RX2"

hdr "5. 调试日志（前台模式全部可见）"
tail -30 /tmp/diag-fg.log | sed 's/^/  /'

hdr "5b. sslocal 临时配置与日志"
SPID=$(pgrep -x sslocal | head -1)
if [ -n "$SPID" ]; then
    echo "-- cmdline:"
    tr '\0' ' ' < /proc/$SPID/cmdline; echo
    CFG=$(tr '\0' ' ' < /proc/$SPID/cmdline | grep -oE '[^ ]*sscli-sslocal-[^ ]*\.json' | head -1)
    if [ -n "$CFG" ] && [ -f "$CFG" ]; then
        echo "-- 配置(密码打码):"
        sed -E 's/("password":)"[^"]*"/\1"***"/' "$CFG" | sed 's/^/  /'
    fi
    echo "-- sslocal 日志文件定位:"
    for LP in /var/lib/sscli/sslocal.log /root/.local/state/sscli/sslocal.log ~/.local/state/sscli/sslocal.log; do
        [ -f "$LP" ] && echo "  $LP ($(stat -c%s "$LP") bytes)" && tail -30 "$LP" | sed 's/^/    /'
    done
    [ -f /root/.local/state/sscli/sslocal.log ] || [ -f ~/.local/state/sscli/sslocal.log ] || echo "  无任何日志文件"
else
    echo "  sslocal 未运行"
fi

hdr "5c. 运行中的 nat OUTPUT 规则（RETURN 应在位）"
iptables -t nat -S OUTPUT | sed 's/^/  /'

hdr "6. 清理重复 iptables 残留并显示终态"
for i in 1 2 3 4 5; do
    iptables -t nat -D OUTPUT -m mark --mark 0x162 -j RETURN 2>/dev/null || break
done
iptables -t nat -S OUTPUT | sed 's/^/  /'
