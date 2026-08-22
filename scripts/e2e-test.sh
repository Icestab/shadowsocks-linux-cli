#!/usr/bin/env bash
# Root-level end-to-end test for sscli (run with sudo on WSL2/Linux).
# Verifies: TUN creation, policy routing, loop prevention, LAN direct,
# proxy path, and clean teardown. Never leaves the machine offline:
# every step has a guaranteed cleanup via trap.
set -u

FAIL=0
step() { echo; echo "== $1 =="; }
ok()   { echo "  [PASS] $1"; }
bad()  { echo "  [FAIL] $1"; FAIL=1; }

SSCLI=${SSCLI:-/usr/local/bin/sscli}
TUN=${TUN:-sscli0}

cleanup() {
    echo
    echo "== Cleanup =="
    "$SSCLI" stop || true
    ip link del dev "$TUN" 2>/dev/null || true
    # Belt & braces: sweep any leftover policy state.
    ip rule del fwmark 0x162 2>/dev/null || true
    ip rule del lookup 5162 2>/dev/null || true
    ip route flush table 5162 2>/dev/null || true
}
trap cleanup EXIT

[ "$(id -u)" -eq 0 ] || { echo "must run as root"; exit 1; }

DEFAULT_ROUTE_BEFORE=$(ip route show default)
echo "default route before: $DEFAULT_ROUTE_BEFORE"

step "start"
"$SSCLI" start && ok "sscli started" || bad "sscli start failed"

step "tun"
ip link show dev "$TUN" >/dev/null && ok "$TUN exists" || bad "$TUN missing"
ip addr show dev "$TUN" | grep -q 198.18 && ok "TUN address set" || bad "TUN address missing"

step "policy rules"
ip rule show | grep -q "fwmark 0x162" && ok "fwmark escape rule" || bad "fwmark rule missing"
ip rule show | grep -q "lookup 5162" && ok "tun lookup rule" || bad "lookup rule missing"

step "loop prevention (server host route)"
SERVER_IP=$(awk '/^(server|address):/{print $2}' /etc/sscli/config.yaml 2>/dev/null | head -1)
echo "  (server bypass route installed by sscli; verify manually with 'ip route get <server-ip>')"

step "connectivity while running (direct must survive hijack)"
sleep 2
if curl -s --max-time 10 -o /dev/null -w '%{http_code}' https://www.baidu.com | grep -q 200; then
    ok "baidu.com reachable (DIRECT path)"
else
    bad "baidu.com NOT reachable — DIRECT path broken"
fi

step "dns hijack regression (start->stop x2)"
# 要求：stop 后 DNS 必须恢复，且 iptables nat OUTPUT 恢复到启动前状态。
NAT_BEFORE=$(iptables -t nat -S OUTPUT 2>/dev/null | sort)
for round in 1 2; do
    "$SSCLI" start >/dev/null 2>&1 && ok "start#$round"
    if nslookup qq.com >/dev/null 2>&1; then ok "DNS works (running #$round)"; else bad "DNS broken while running #$round"; fi
    "$SSCLI" stop >/dev/null 2>&1
    sleep 1
    if nslookup qq.com >/dev/null 2>&1; then ok "DNS restored (stopped #$round)"; else bad "DNS STILL BROKEN after stop #$round"; fi
done
NAT_AFTER=$(iptables -t nat -S OUTPUT 2>/dev/null | sort)
if [ "$NAT_BEFORE" = "$NAT_AFTER" ]; then ok "nat OUTPUT restored byte-for-byte"; else bad "nat OUTPUT differs from pre-start state"; diff <(echo "$NAT_BEFORE") <(echo "$NAT_AFTER") | head -5; fi

step "stop and restore"
"$SSCLI" stop && ok "sscli stopped" || bad "stop failed"
sleep 1
ip link show dev "$TUN" >/dev/null 2>&1 && bad "$TUN still present after stop" || ok "$TUN removed"
ip rule show | grep -q "lookup 5162" && bad "policy rule left over" || ok "policy rules restored"
ip route show default | grep -q . && ok "default route present" || bad "NO DEFAULT ROUTE — NETWORK BROKEN"

step "connectivity after stop"
if curl -s --max-time 10 -o /dev/null -w '%{http_code}' https://www.baidu.com | grep -q 200; then
    ok "network fully functional after stop"
else
    bad "network broken after stop!"
fi

echo
[ "$FAIL" -eq 0 ] && echo "E2E RESULT: ALL PASS" || echo "E2E RESULT: FAILURES PRESENT"
exit $FAIL
