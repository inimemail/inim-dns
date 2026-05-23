#!/bin/bash

set -o pipefail

BASE_DIR="/etc/ai_unlock"
CUSTOM_DOMAIN_FILE="$BASE_DIR/custom_domains.conf"
NODE_WHITELIST_FILE="$BASE_DIR/node_whitelist.conf"
DNSMASQ_CONF="/etc/dnsmasq.d/ai_unlock.conf"
SNI_CONF="/etc/sniproxy.conf"
SNI_CONF_DIR="/etc/sniproxy/sniproxy.conf"
SNI_DEFAULT="/etc/default/sniproxy"
SNI_SYSTEMD_SERVICE="/etc/systemd/system/sniproxy.service"
RESOLV_BACKUP="$BASE_DIR/resolv.conf.bak"
UNLOCK_RESOLV_BACKUP="$BASE_DIR/unlock-resolv.conf.bak"
FIREWALL_CHAIN="AI_UNLOCK_DNS"
SYNC_SCRIPT="$BASE_DIR/sync_firewall.sh"
SYSTEMD_SERVICE="/etc/systemd/system/ai-unlock-firewall.service"
PANEL_SCRIPT="$BASE_DIR/panel.py"
PANEL_SERVICE="/etc/systemd/system/ai-unlock-panel.service"
PANEL_AUTH_FILE="$BASE_DIR/panel_auth.conf"
PANEL_SECRET_FILE="$BASE_DIR/panel_secret"
PANEL_TOKEN_FILE="$BASE_DIR/node_join_token"
PANEL_NODES_FILE="$BASE_DIR/nodes.json"
PANEL_PORT_FILE="$BASE_DIR/panel_port.conf"
PANEL_DEFAULT_PORT="8088"

AI_CHECK_URLS=(
  "https://chatgpt.com"
  "https://claude.ai"
  "https://gemini.google.com"
  "https://copilot.microsoft.com"
  "https://perplexity.ai"
  "https://grok.com"
  "https://deepseek.com"
  "https://mistral.ai"
)

PUBLIC_DNS_SERVERS=("1.1.1.1" "8.8.8.8")

OPENAI_DOMAINS=("openai.com" "chatgpt.com" "oaiusercontent.com" "oaistatic.com")
ANTHROPIC_DOMAINS=("anthropic.com" "claude.ai" "claude.com" "claudeusercontent.com")
GOOGLE_DOMAINS=("google.com" "googleapis.com" "gstatic.com" "googleusercontent.com" "ggpht.com" "ytimg.com" "withgoogle.com" "googletagmanager.com" "googlevideo.com" "gemini.google.com" "aistudio.google.com")
PERPLEXITY_DOMAINS=("perplexity.ai" "perplexity.com")
XAI_DOMAINS=("x.ai" "grok.com" "api.x.ai")
MICROSOFT_DOMAINS=("copilot.microsoft.com" "bing.com")
MIDJOURNEY_DOMAINS=("midjourney.com" "alpha.midjourney.com")
DEEPSEEK_DOMAINS=("deepseek.com" "chat.deepseek.com" "api.deepseek.com" "platform.deepseek.com")
MISTRAL_DOMAINS=("mistral.ai" "chat.mistral.ai" "console.mistral.ai" "api.mistral.ai")
OTHER_DOMAINS=("character.ai" "poe.com" "openrouter.ai" "platform.openrouter.ai" "meta.ai" "you.com")

BASE_DOMAINS=("${OPENAI_DOMAINS[@]}" "${ANTHROPIC_DOMAINS[@]}" "${GOOGLE_DOMAINS[@]}" "${PERPLEXITY_DOMAINS[@]}" "${XAI_DOMAINS[@]}" "${MICROSOFT_DOMAINS[@]}" "${MIDJOURNEY_DOMAINS[@]}" "${DEEPSEEK_DOMAINS[@]}" "${MISTRAL_DOMAINS[@]}" "${OTHER_DOMAINS[@]}")

SERVER_IP=""
FIREWALL_BACKEND=""
NODE_WHITELIST_IPS=()

# ================= 基础输出与检查函数 =================
color() { printf "\033[%sm%s\033[0m" "$1" "$2"; }
info() { printf "%b\n" "$(color 36 "ℹ️  $*")"; }
ok() { printf "%b\n" "$(color 32 "✅ $*")"; }
warn() { printf "%b\n" "$(color 33 "⚠️  $*")"; }
err() { printf "%b\n" "$(color 31 "❌ $*")"; }
pause() { read -n 1 -s -r -p "按任意键继续..."; printf "\n"; }

ensure_root() { [ "$EUID" -ne 0 ] && err "请使用 root 权限运行此脚本。" && exit 1; }
command_exists() { command -v "$1" >/dev/null 2>&1; }

ensure_base_dir() {
  mkdir -p "$BASE_DIR"
  touch "$CUSTOM_DOMAIN_FILE" "$NODE_WHITELIST_FILE"
}

detect_public_ip() {
  if [ -n "$SERVER_IP" ]; then printf '%s\n' "$SERVER_IP"; return; fi
  SERVER_IP="$(curl -fs4 --max-time 5 https://ifconfig.me 2>/dev/null || true)"
  if [ -z "$SERVER_IP" ] && command_exists hostname; then SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"; fi
  if [ -z "$SERVER_IP" ]; then read -r -p "请输入解锁机公网 IP: " SERVER_IP; fi
  printf '%s\n' "$SERVER_IP"
}

detect_node_public_ip() {
  local ip=""
  if command_exists curl; then
    ip="$(curl -k -fs4 --max-time 5 https://1.1.1.1/cdn-cgi/trace 2>/dev/null | awk -F= '/^ip=/ {print $2; exit}')"
    if [ -z "$ip" ]; then ip="$(curl -fs4 --max-time 5 https://ifconfig.me 2>/dev/null || true)"; fi
  fi
  printf '%s\n' "$ip"
}

install_packages() {
  local packages=("$@")
  if command_exists apt-get; then apt-get update -y; DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}"
  elif command_exists dnf; then dnf install -y "${packages[@]}"
  elif command_exists yum; then yum install -y "${packages[@]}"
  elif command_exists pacman; then pacman -Sy --noconfirm "${packages[@]}"
  elif command_exists zypper; then zypper --non-interactive install -y "${packages[@]}"
  elif command_exists apk; then apk add --no-cache "${packages[@]}"
  else err "未找到包管理器。"; return 1; fi
}

# 强杀清理逻辑 (完全静默处理，避免输出乱码数字)
release_port_53() {
  if command_exists systemctl && systemctl is-active systemd-resolved >/dev/null 2>&1; then
    systemctl stop systemd-resolved 2>/dev/null || true
    systemctl disable systemd-resolved 2>/dev/null || true
  fi
  if command_exists fuser; then fuser -k -9 53/tcp 53/udp >/dev/null 2>&1 || true; fi
}

release_port_443() {
  if command_exists fuser; then fuser -k -9 443/tcp >/dev/null 2>&1 || true; fi
  if command_exists killall; then killall -9 sniproxy >/dev/null 2>&1 || true; fi
}

service_restart() { 
  local svc="$1"
  if [ "$svc" == "sniproxy" ]; then release_port_443; sleep 1; fi
  if command_exists systemctl; then systemctl restart "$svc"; elif command_exists service; then service "$svc" restart; fi
}
service_enable() { local svc="$1"; if command_exists systemctl; then systemctl enable "$svc" >/dev/null 2>&1; fi; }
service_start() { 
  local svc="$1"
  if [ "$svc" == "sniproxy" ]; then release_port_443; sleep 1; fi
  if command_exists systemctl; then systemctl start "$svc"; elif command_exists service; then service "$svc" start; fi
}
service_stop() { local svc="$1"; if command_exists systemctl; then systemctl stop "$svc" >/dev/null 2>&1 || true; elif command_exists service; then service "$svc" stop >/dev/null 2>&1 || true; fi; }
service_status() { local svc="$1"; if command_exists systemctl; then systemctl is-active "$svc" >/dev/null 2>&1 && echo "active" || echo "inactive"; else echo "unknown"; fi; }

enable_sniproxy_default() {
  if [ -f "$SNI_DEFAULT" ]; then
    if grep -q '^ENABLED=' "$SNI_DEFAULT"; then
      sed -i 's/^ENABLED=.*/ENABLED=1/' "$SNI_DEFAULT"
    else
      printf '\nENABLED=1\n' >> "$SNI_DEFAULT"
    fi
  else
    printf 'ENABLED=1\n' > "$SNI_DEFAULT"
  fi
}

install_sniproxy_systemd_unit() {
  command_exists systemctl || return 0
  cat > "$SNI_SYSTEMD_SERVICE" <<EOF
[Unit]
Description=HTTPS SNI Proxy
Documentation=man:sniproxy(8)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/sbin/sniproxy -f -c $SNI_CONF
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
}

validate_sniproxy_config() {
  command_exists timeout || return 0
  command_exists sniproxy || return 0

  local log="/tmp/sniproxy-config-test.log" rc
  release_port_443
  timeout 3s /usr/sbin/sniproxy -f -c "$SNI_CONF" >"$log" 2>&1
  rc=$?
  release_port_443

  if [ "$rc" -eq 124 ]; then
    return 0
  fi

  err "SNIProxy 配置校验失败："
  cat "$log" 2>/dev/null || true
  return 1
}

show_sniproxy_failure() {
  warn "SNIProxy 启动失败，下面是系统日志："
  if command_exists systemctl; then
    systemctl status sniproxy --no-pager -l 2>/dev/null || true
  fi
  if command_exists journalctl; then
    journalctl -u sniproxy --no-pager -n 30 2>/dev/null || true
  fi
  if command_exists ss; then
    info "当前占用 443 端口的进程："
    ss -ltnp 'sport = :443' 2>/dev/null || true
  fi
}

# ================= 防火墙管理核心 =================
firewall_detect_backend() {
  if command_exists nft; then echo "nftables"; return; fi
  if command_exists iptables; then echo "iptables"; return; fi
  echo "none"
}

firewall_backend_ready() { [ "$(firewall_detect_backend)" != "none" ]; }

install_firewall_tools() {
  firewall_backend_ready && return 0
  install_packages nftables iptables || true
  firewall_backend_ready
}

firewall_init_backend() {
  FIREWALL_BACKEND="$(firewall_detect_backend)"
  if [ "$FIREWALL_BACKEND" = "nftables" ]; then
    if ! nft list table inet ai_unlock >/dev/null 2>&1; then nft add table inet ai_unlock; fi
    if nft list chain inet ai_unlock input >/dev/null 2>&1; then nft flush chain inet ai_unlock input; else nft add chain inet ai_unlock input '{ type filter hook input priority 0; policy accept; }'; fi
    if ! nft list set inet ai_unlock node_whitelist >/dev/null 2>&1; then nft add set inet ai_unlock node_whitelist '{ type ipv4_addr; flags interval; }'; fi
    nft add rule inet ai_unlock input iifname "lo" accept 2>/dev/null || true
    nft add rule inet ai_unlock input ip protocol udp udp dport 53 ip saddr @node_whitelist accept 2>/dev/null || true
    nft add rule inet ai_unlock input ip protocol tcp tcp dport 53 ip saddr @node_whitelist accept 2>/dev/null || true
    nft add rule inet ai_unlock input ip protocol udp udp dport 53 drop 2>/dev/null || true
    nft add rule inet ai_unlock input ip protocol tcp tcp dport 53 drop 2>/dev/null || true
    return 0
  fi
  if [ "$FIREWALL_BACKEND" = "iptables" ]; then
    if ! iptables -nL "$FIREWALL_CHAIN" >/dev/null 2>&1; then iptables -N "$FIREWALL_CHAIN" 2>/dev/null || true; iptables -A "$FIREWALL_CHAIN" -j DROP 2>/dev/null || true; fi
    iptables -C "$FIREWALL_CHAIN" -i lo -j ACCEPT 2>/dev/null || iptables -I "$FIREWALL_CHAIN" 1 -i lo -j ACCEPT 2>/dev/null || true
    iptables -C INPUT -p udp --dport 53 -j "$FIREWALL_CHAIN" 2>/dev/null || iptables -I INPUT -p udp --dport 53 -j "$FIREWALL_CHAIN" 2>/dev/null || true
    iptables -C INPUT -p tcp --dport 53 -j "$FIREWALL_CHAIN" 2>/dev/null || iptables -I INPUT -p tcp --dport 53 -j "$FIREWALL_CHAIN" 2>/dev/null || true
    return 0
  fi
  return 1
}

load_node_whitelist() {
  NODE_WHITELIST_IPS=()
  [ -f "$NODE_WHITELIST_FILE" ] || return 0
  while IFS= read -r line; do
    line="$(echo "$line" | sed 's/^[ \t]*//;s/[ \t]*$//')"
    [ -z "$line" ] && continue
    case "$line" in \#*) continue ;; esac
    NODE_WHITELIST_IPS+=("$line")
  done < "$NODE_WHITELIST_FILE"
}

save_node_whitelist() {
  : > "$NODE_WHITELIST_FILE"
  for ip in "${NODE_WHITELIST_IPS[@]}"; do printf '%s\n' "$ip" >> "$NODE_WHITELIST_FILE"; done
}

sync_firewall_whitelist() {
  firewall_init_backend || return 1
  load_node_whitelist
  if [ "$FIREWALL_BACKEND" = "nftables" ]; then
    nft flush set inet ai_unlock node_whitelist 2>/dev/null || true
    for ip in "${NODE_WHITELIST_IPS[@]}"; do
      validate_ipv4 "$ip" || continue
      nft add element inet ai_unlock node_whitelist "{ $ip }" 2>/dev/null || true
    done
    ok "nftables 白名单已同步。"
    return 0
  fi
  if [ "$FIREWALL_BACKEND" = "iptables" ]; then
    iptables -F "$FIREWALL_CHAIN" 2>/dev/null || true
    iptables -A "$FIREWALL_CHAIN" -i lo -j ACCEPT 2>/dev/null || true
    for ip in "${NODE_WHITELIST_IPS[@]}"; do
      validate_ipv4 "$ip" || continue
      iptables -A "$FIREWALL_CHAIN" -p udp --dport 53 -s "$ip" -j ACCEPT 2>/dev/null || true
      iptables -A "$FIREWALL_CHAIN" -p tcp --dport 53 -s "$ip" -j ACCEPT 2>/dev/null || true
    done
    iptables -A "$FIREWALL_CHAIN" -p udp --dport 53 -j DROP 2>/dev/null || true
    iptables -A "$FIREWALL_CHAIN" -p tcp --dport 53 -j DROP 2>/dev/null || true
    ok "iptables 白名单已同步。"
    return 0
  fi
  return 1
}

setup_firewall_persistence() {
  cat > "$SYNC_SCRIPT" << 'EOF'
#!/bin/bash
NODE_WHITELIST_FILE="/etc/ai_unlock/node_whitelist.conf"
FIREWALL_CHAIN="AI_UNLOCK_DNS"
if command -v nft >/dev/null 2>&1 && nft list table inet ai_unlock >/dev/null 2>&1; then
  if nft list chain inet ai_unlock input >/dev/null 2>&1; then
    nft flush chain inet ai_unlock input 2>/dev/null || true
  else
    nft add chain inet ai_unlock input '{ type filter hook input priority 0; policy accept; }' 2>/dev/null || true
  fi
  nft flush set inet ai_unlock node_whitelist 2>/dev/null || true
  nft add rule inet ai_unlock input iifname "lo" accept 2>/dev/null || true
  [ -f "$NODE_WHITELIST_FILE" ] || exit 0
  while IFS= read -r ip; do [[ -z "$ip" || "$ip" == \#* ]] && continue; nft add element inet ai_unlock node_whitelist "{ $ip }" 2>/dev/null || true; done < "$NODE_WHITELIST_FILE"
  nft add rule inet ai_unlock input ip protocol udp udp dport 53 ip saddr @node_whitelist accept 2>/dev/null || true
  nft add rule inet ai_unlock input ip protocol tcp tcp dport 53 ip saddr @node_whitelist accept 2>/dev/null || true
  nft add rule inet ai_unlock input ip protocol udp udp dport 53 drop 2>/dev/null || true
  nft add rule inet ai_unlock input ip protocol tcp tcp dport 53 drop 2>/dev/null || true
elif command -v iptables >/dev/null 2>&1 && iptables -nL "$FIREWALL_CHAIN" >/dev/null 2>&1; then
  iptables -F "$FIREWALL_CHAIN" 2>/dev/null || true
  iptables -A "$FIREWALL_CHAIN" -i lo -j ACCEPT 2>/dev/null || true
  [ -f "$NODE_WHITELIST_FILE" ] || exit 0
  while IFS= read -r ip; do
    [[ -z "$ip" || "$ip" == \#* ]] && continue
    iptables -A "$FIREWALL_CHAIN" -p udp --dport 53 -s "$ip" -j ACCEPT 2>/dev/null || true
    iptables -A "$FIREWALL_CHAIN" -p tcp --dport 53 -s "$ip" -j ACCEPT 2>/dev/null || true
  done < "$NODE_WHITELIST_FILE"
  iptables -A "$FIREWALL_CHAIN" -p udp --dport 53 -j DROP 2>/dev/null || true; iptables -A "$FIREWALL_CHAIN" -p tcp --dport 53 -j DROP 2>/dev/null || true
fi
EOF
  chmod +x "$SYNC_SCRIPT"

  cat > "$SYSTEMD_SERVICE" <<EOF
[Unit]
Description=AI Unlock DNS Firewall Sync
After=network.target iptables.service nftables.service firewalld.service ufw.service

[Service]
Type=oneshot
ExecStart=/bin/bash $SYNC_SCRIPT
RemainAfterExit=true

[Install]
WantedBy=multi-user.target
EOF

  if command_exists systemctl; then
    systemctl daemon-reload
    systemctl enable ai-unlock-firewall.service >/dev/null 2>&1
  fi
}

remove_firewall_rules() {
  FIREWALL_BACKEND="$(firewall_detect_backend)"
  if [ "$FIREWALL_BACKEND" = "nftables" ]; then
    nft delete table inet ai_unlock 2>/dev/null || true
  elif [ "$FIREWALL_BACKEND" = "iptables" ]; then
    while iptables -D INPUT -p udp --dport 53 -j "$FIREWALL_CHAIN" 2>/dev/null; do :; done
    while iptables -D INPUT -p tcp --dport 53 -j "$FIREWALL_CHAIN" 2>/dev/null; do :; done
    iptables -F "$FIREWALL_CHAIN" 2>/dev/null || true
    iptables -X "$FIREWALL_CHAIN" 2>/dev/null || true
  fi
}

validate_ipv4() {
  local ip="$1" a b c d extra; IFS=. read -r a b c d extra <<EOF
$ip
EOF
  [ -n "$a" ] && [ -n "$b" ] && [ -n "$c" ] && [ -n "$d" ] && [ -z "$extra" ] || return 1
  for octet in "$a" "$b" "$c" "$d"; do case "$octet" in ''|*[!0-9]*) return 1 ;; esac; [ "$octet" -ge 0 ] 2>/dev/null && [ "$octet" -le 255 ] 2>/dev/null || return 1; done
  return 0
}

# ================= 连通性测试与环境检查 =================
http_code_is_unlocked() {
  local code="$1"
  case "$code" in
    2*) return 0 ;;
    *) return 1 ;;
  esac
}

print_ai_http_result() {
  local prefix="$1" url="$2" code="$3"
  if [ -z "$code" ] || [ "$code" = "000" ]; then
    printf "  %b %s\n" "$(color 31 "[$prefix失败]")" "$url"
    return 1
  fi
  if http_code_is_unlocked "$code"; then
    printf "  %b %s\n" "$(color 32 "[$prefix通过]")" "$url"
    return 0
  fi
  case "$code" in
    401) printf "  %b %s\n" "$(color 33 "[$prefix需认证]")" "$url" ;;
    3*) printf "  %b %s\n" "$(color 33 "[$prefix跳转]")" "$url" ;;
    *) printf "  %b %s\n" "$(color 31 "[$prefix失败]")" "$url" ;;
  esac
  return 1
}

check_ai_endpoint() {
  local url="$1" code
  code="$(curl -k -sS -L --connect-timeout 5 --max-time 10 -o /dev/null -w '%{http_code}' "$url" 2>/dev/null || true)"
  print_ai_http_result "AI" "$url" "$code"
}

show_unlock_summary() {
  clear
  printf "%b\n" "$(color 36 "======================================")"
  printf "%b\n" "$(color 36 "           运行状态检测")"
  printf "%b\n" "$(color 36 "======================================")"
  printf "公网 IP: %s\n" "$(detect_public_ip)"
  echo "--------------------------------------"
  printf "核心服务状态：\n"
  printf "  dnsmasq: %s\n" "$(service_status dnsmasq)"
  printf "  sniproxy: %s\n" "$(service_status sniproxy)"
  
  if [ "$(service_status sniproxy)" != "active" ]; then
    warn "SNIProxy 未运行！系统可能存在其他进程死锁 443 端口。"
  fi
  
  echo "--------------------------------------"
  FIREWALL_BACKEND="$(firewall_detect_backend)"
  printf "防火墙后端: %s (放行 IP 数: %s)\n" "$FIREWALL_BACKEND" "$([ -s "$NODE_WHITELIST_FILE" ] && wc -l < "$NODE_WHITELIST_FILE" || echo 0)"
  info "若节点机 DNS 解析超时，必须在云服务商网页控制台开放 53 端口！"
  echo "--------------------------------------"
  printf "本机 AI 连通性：\n"
  local url ok_count=0
  for url in "${AI_CHECK_URLS[@]}"; do if check_ai_endpoint "$url"; then ok_count=$((ok_count + 1)); fi; done
  printf "  通过项: %s/%s\n" "$ok_count" "${#AI_CHECK_URLS[@]}"
}

show_service_status_detail() {
  local svc="$1"
  printf "\n%b\n" "$(color 36 "===== $svc 状态 =====")"
  if command_exists systemctl; then
    systemctl status "$svc" --no-pager -l 2>/dev/null || true
  elif command_exists service; then
    service "$svc" status 2>/dev/null || true
  else
    warn "当前系统没有 systemctl/service，无法查看服务状态。"
  fi
}

show_service_logs() {
  local svc="$1"
  printf "\n%b\n" "$(color 36 "===== $svc 最近日志 =====")"
  if command_exists journalctl; then
    journalctl -u "$svc" --no-pager -n 80 2>/dev/null || true
  else
    show_service_status_detail "$svc"
  fi
}

show_unlock_logs() {
  show_service_status_detail dnsmasq
  show_service_logs dnsmasq
  show_service_status_detail sniproxy
  show_service_logs sniproxy
  if command_exists ss; then
    printf "\n%b\n" "$(color 36 "===== 端口监听 =====")"
    ss -lntup 2>/dev/null | awk 'NR==1 || /:53|:443/'
  fi
  printf "\n%b\n" "$(color 36 "===== 节点白名单 =====")"
  if [ -s "$NODE_WHITELIST_FILE" ]; then
    cat "$NODE_WHITELIST_FILE"
  else
    printf "  暂无节点 IP\n"
  fi
  printf "\n%b\n" "$(color 36 "===== 防火墙规则 =====")"
  if command_exists nft && nft list table inet ai_unlock >/dev/null 2>&1; then
    nft list table inet ai_unlock 2>/dev/null || true
  elif command_exists iptables; then
    iptables -nL "$FIREWALL_CHAIN" 2>/dev/null || true
  else
    warn "未检测到 nftables/iptables。"
  fi
}

restart_unlock_services() {
  update_rules || return 1
  ok "解锁规则已重新生成，服务已重启。"
  printf "  dnsmasq: %s\n" "$(service_status dnsmasq)"
  printf "  sniproxy: %s\n" "$(service_status sniproxy)"
}

stop_unlock_services() {
  service_stop dnsmasq
  service_stop sniproxy
  if command_exists killall; then killall -9 sniproxy >/dev/null 2>&1 || true; fi
  ok "解锁服务已暂停。"
  printf "  dnsmasq: %s\n" "$(service_status dnsmasq)"
  printf "  sniproxy: %s\n" "$(service_status sniproxy)"
}

# ================= Web 面板 =================
random_string() {
  if command_exists tr; then tr -dc 'A-Za-z0-9' </dev/urandom 2>/dev/null | head -c "${1:-24}"; else date +%s%N; fi
}

panel_port() {
  if [ -s "$PANEL_PORT_FILE" ]; then tr -cd '0-9' < "$PANEL_PORT_FILE"; else printf '%s' "$PANEL_DEFAULT_PORT"; fi
}

write_panel_script() {
  ensure_base_dir
  cat > "$PANEL_SCRIPT" <<'PYEOF'
#!/usr/bin/env python3
import base64, hashlib, hmac, html, http.cookies, http.server, json, os, re, secrets, socketserver, subprocess, time, urllib.parse

BASE_DIR = "/etc/ai_unlock"
CUSTOM_DOMAIN_FILE = f"{BASE_DIR}/custom_domains.conf"
NODE_WHITELIST_FILE = f"{BASE_DIR}/node_whitelist.conf"
NODES_FILE = f"{BASE_DIR}/nodes.json"
AUTH_FILE = f"{BASE_DIR}/panel_auth.conf"
SECRET_FILE = f"{BASE_DIR}/panel_secret"
TOKEN_FILE = f"{BASE_DIR}/node_join_token"
PORT_FILE = f"{BASE_DIR}/panel_port.conf"
DNSMASQ_CONF = "/etc/dnsmasq.d/ai_unlock.conf"
SNI_CONF = "/etc/sniproxy.conf"
SNI_CONF_DIR = "/etc/sniproxy/sniproxy.conf"
SNI_DEFAULT = "/etc/default/sniproxy"
SNI_SYSTEMD_SERVICE = "/etc/systemd/system/sniproxy.service"
FIREWALL_CHAIN = "AI_UNLOCK_DNS"
PUBLIC_DNS = ["1.1.1.1", "8.8.8.8"]
AI_URLS = ["https://chatgpt.com","https://claude.ai","https://gemini.google.com","https://copilot.microsoft.com","https://perplexity.ai","https://grok.com","https://deepseek.com","https://mistral.ai"]
BASE_DOMAINS = ["openai.com","chatgpt.com","oaiusercontent.com","oaistatic.com","anthropic.com","claude.ai","claude.com","claudeusercontent.com","google.com","googleapis.com","gstatic.com","googleusercontent.com","ggpht.com","ytimg.com","withgoogle.com","googletagmanager.com","googlevideo.com","gemini.google.com","aistudio.google.com","perplexity.ai","perplexity.com","x.ai","grok.com","api.x.ai","copilot.microsoft.com","bing.com","midjourney.com","alpha.midjourney.com","deepseek.com","chat.deepseek.com","api.deepseek.com","platform.deepseek.com","mistral.ai","chat.mistral.ai","console.mistral.ai","api.mistral.ai","character.ai","poe.com","openrouter.ai","platform.openrouter.ai","meta.ai","you.com"]

SESSIONS = {}
FAILS = {}

CSS = r"""
:root{--bg:#f5f7fb;--panel:#fff;--ink:#182230;--muted:#657386;--line:#d9e1ea;--green:#107569;--blue:#27548a;--red:#b42318;--amber:#a15c07}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;letter-spacing:0}a{text-decoration:none;color:inherit}button,input,textarea{font:inherit}.side{position:fixed;inset:0 auto 0 0;width:230px;background:#111b25;color:#edf4fb;padding:22px 18px;display:flex;flex-direction:column;gap:20px}.brand{font-size:20px;font-weight:800}.nav{display:grid;gap:8px}.nav a,.logout button{width:100%;display:block;text-align:left;border:0;border-radius:8px;background:transparent;color:#d9e3ee;padding:10px 12px;cursor:pointer}.nav a:hover,.logout button:hover{background:#1e2b38;color:#fff}.logout{margin-top:auto}.main{margin-left:230px;padding:28px;min-height:100vh;display:grid;gap:18px;align-content:start}.top{display:flex;align-items:center;justify-content:space-between;gap:16px}.top h1{margin:0;font-size:26px}.grid{display:grid;gap:16px}.metrics{grid-template-columns:repeat(4,minmax(0,1fr))}.split{grid-template-columns:repeat(2,minmax(0,1fr))}.card,.metric{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:18px;box-shadow:0 1px 2px rgba(16,24,40,.04)}.metric span{display:block;color:var(--muted)}.metric strong{display:block;margin-top:6px;font-size:22px;overflow-wrap:anywhere}.head{display:flex;align-items:flex-start;justify-content:space-between;gap:14px;margin-bottom:14px}.head h2{margin:0;font-size:18px}.head p{margin:2px 0 0;color:var(--muted)}.actions{display:flex;gap:10px;flex-wrap:wrap}button{border:0;border-radius:8px;background:var(--green);color:#fff;padding:9px 14px;font-weight:700;cursor:pointer;white-space:nowrap}.danger{background:var(--red)}.ghost{background:#eef3f7;color:var(--ink)}input,textarea{width:100%;border:1px solid var(--line);border-radius:8px;background:#fff;padding:10px 11px;color:var(--ink);outline:none}textarea{resize:vertical}.stack{display:grid;gap:12px}label{display:grid;gap:6px;color:var(--muted)}.row{display:grid;grid-template-columns:1fr auto;gap:10px}.inline{display:grid;grid-template-columns:135px 1fr 1fr auto;gap:8px}.table{overflow:auto}table{width:100%;border-collapse:collapse}th,td{border-bottom:1px solid var(--line);padding:10px;text-align:left;vertical-align:middle}th{color:var(--muted);font-weight:700}code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}.cmd{margin:0;background:#101820;color:#edf6ff;border-radius:8px;padding:14px;white-space:pre-wrap;overflow:auto}.checks{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.check{display:flex;justify-content:space-between;gap:12px;border:1px solid var(--line);border-radius:8px;padding:10px 12px}.ok{color:var(--green)}.bad{color:var(--red)}.warn{color:var(--amber)}.alert{border-radius:8px;padding:11px 13px;border:1px solid var(--line);background:#fff}.alert.ok{border-color:#9bd3c7;background:#effaf7}.alert.bad{border-color:#f0b1ac;background:#fff3f2}.pills{display:flex;flex-wrap:wrap;gap:8px}.pill{border:1px solid var(--line);border-radius:999px;padding:6px 10px;background:#f9fbfd}.domain{display:flex;align-items:center;justify-content:space-between;border:1px solid var(--line);border-radius:8px;padding:9px 10px;margin-bottom:8px}.muted{color:var(--muted)}.login{min-height:100vh;display:grid;place-items:center;padding:24px;background:linear-gradient(180deg,#f6f8fb,#eaf0f6)}.login-box{width:min(420px,100%);background:#fff;border:1px solid var(--line);border-radius:8px;padding:28px;display:grid;gap:16px;box-shadow:0 12px 40px rgba(16,24,40,.12)}.login-box h1{margin:0;font-size:28px}.login-box p{margin:0;color:var(--muted)}@media(max-width:920px){.side{position:static;width:auto;flex-direction:row;align-items:center;flex-wrap:wrap}.nav{display:flex;flex-wrap:wrap}.logout{margin-left:auto;margin-top:0}.main{margin-left:0;padding:18px}.metrics,.split,.checks{grid-template-columns:1fr}.inline{grid-template-columns:1fr}}
"""

def run(cmd, ok=False):
    try:
        return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=20).returncode == 0
    except Exception:
        return ok

def out(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True, timeout=12).strip()
    except Exception:
        return ""

def exists(cmd):
    return run(["sh","-c",f"command -v {cmd} >/dev/null 2>&1"])

def read(path, default=""):
    try:
        with open(path, "r") as f: return f.read()
    except Exception:
        return default

def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f: f.write(data)

def valid_ip(ip):
    p = ip.strip().split(".")
    return len(p) == 4 and all(x.isdigit() and 0 <= int(x) <= 255 for x in p)

def clean_domain(s):
    s = s.strip().lower()
    s = re.sub(r"^[a-z][a-z0-9+.-]*://", "", s)
    s = re.sub(r"^\*\.", "", s).split("/")[0].split(":")[0]
    return s if "." in s and re.fullmatch(r"[a-z0-9.-]+", s or "") else ""

def public_ip():
    ip = out(["curl","-fs4","--max-time","5","https://ifconfig.me"])
    if valid_ip(ip): return ip
    return out(["sh","-c","hostname -I 2>/dev/null | awk '{print $1}'"]) or "0.0.0.0"

def service_status(name):
    return "active" if run(["systemctl","is-active",name]) else "inactive"

def load_nodes():
    if os.path.exists(NODES_FILE):
        try:
            return json.loads(read(NODES_FILE, "[]"))
        except Exception:
            pass
    nodes = []
    for line in read(NODE_WHITELIST_FILE).splitlines():
        ip = line.strip()
        if valid_ip(ip):
            nodes.append({"id": secrets.token_hex(8), "ip": ip, "name": "", "note": "", "created": time.strftime("%Y-%m-%d %H:%M")})
    save_nodes(nodes, sync=False)
    return nodes

def save_nodes(nodes, sync=True):
    write(NODES_FILE, json.dumps(nodes, ensure_ascii=False, indent=2))
    write(NODE_WHITELIST_FILE, "".join(n["ip"] + "\n" for n in nodes if valid_ip(n.get("ip",""))))
    if sync:
        sync_firewall(nodes)

def load_custom_domains():
    res = []
    for line in read(CUSTOM_DOMAIN_FILE).splitlines():
        d = clean_domain(line)
        if d and d not in res:
            res.append(d)
    return res

def save_custom_domains(domains):
    write(CUSTOM_DOMAIN_FILE, "".join(d + "\n" for d in domains))
    update_rules()

def all_domains():
    seen, res = set(), []
    for d in list(BASE_DOMAINS) + load_custom_domains():
        d = clean_domain(d)
        if d and d not in seen:
            seen.add(d); res.append(d)
    return res

def firewall_backend():
    if exists("nft"): return "nftables"
    if exists("iptables"): return "iptables"
    return "none"

def sync_firewall(nodes):
    backend = firewall_backend()
    if backend == "nftables":
        run(["nft","add","table","inet","ai_unlock"], True)
        run(["nft","add","set","inet","ai_unlock","node_whitelist","{ type ipv4_addr; flags interval; }"], True)
        if run(["nft","list","chain","inet","ai_unlock","input"]):
            run(["nft","flush","chain","inet","ai_unlock","input"], True)
        else:
            run(["nft","add","chain","inet","ai_unlock","input","{ type filter hook input priority 0; policy accept; }"], True)
        run(["nft","flush","set","inet","ai_unlock","node_whitelist"], True)
        for n in nodes:
            if valid_ip(n.get("ip","")):
                run(["nft","add","element","inet","ai_unlock","node_whitelist", "{ %s }" % n["ip"]], True)
        for rule in [
            ["iifname","lo","accept"],
            ["ip","protocol","udp","udp","dport","53","ip","saddr","@node_whitelist","accept"],
            ["ip","protocol","tcp","tcp","dport","53","ip","saddr","@node_whitelist","accept"],
            ["ip","protocol","udp","udp","dport","53","drop"],
            ["ip","protocol","tcp","tcp","dport","53","drop"],
        ]:
            run(["nft","add","rule","inet","ai_unlock","input"] + rule, True)
    elif backend == "iptables":
        if not run(["iptables","-nL",FIREWALL_CHAIN]):
            run(["iptables","-N",FIREWALL_CHAIN], True)
        run(["iptables","-F",FIREWALL_CHAIN], True)
        run(["iptables","-A",FIREWALL_CHAIN,"-i","lo","-j","ACCEPT"], True)
        for n in nodes:
            ip = n.get("ip","")
            if valid_ip(ip):
                run(["iptables","-A",FIREWALL_CHAIN,"-p","udp","--dport","53","-s",ip,"-j","ACCEPT"], True)
                run(["iptables","-A",FIREWALL_CHAIN,"-p","tcp","--dport","53","-s",ip,"-j","ACCEPT"], True)
        run(["iptables","-A",FIREWALL_CHAIN,"-p","udp","--dport","53","-j","DROP"], True)
        run(["iptables","-A",FIREWALL_CHAIN,"-p","tcp","--dport","53","-j","DROP"], True)
        if not run(["iptables","-C","INPUT","-p","udp","--dport","53","-j",FIREWALL_CHAIN]):
            run(["iptables","-I","INPUT","-p","udp","--dport","53","-j",FIREWALL_CHAIN], True)
        if not run(["iptables","-C","INPUT","-p","tcp","--dport","53","-j",FIREWALL_CHAIN]):
            run(["iptables","-I","INPUT","-p","tcp","--dport","53","-j",FIREWALL_CHAIN], True)

def update_rules():
    ip = public_ip()
    dns = "# generated by ai_unlock panel\nport=53\nlisten-address=0.0.0.0\nbind-interfaces\nno-resolv\n"
    dns += "".join(f"server={s}\n" for s in PUBLIC_DNS)
    dns += "cache-size=10000\ndomain-needed\nbogus-priv\n"
    for d in all_domains():
        dns += f"local=/{d}/\naddress=/{d}/{ip}\n"
    write(DNSMASQ_CONF, dns)
    listen = "443" if "inet6" in out(["ip","-6","addr","show","scope","global"]) else "0.0.0.0:443"
    sni = f"user daemon\npidfile /var/run/sniproxy.pid\n\nerror_log {{\n    syslog daemon\n    priority notice\n}}\n\nlisten {listen} {{\n    proto tls\n    table https_hosts\n}}\n\ntable https_hosts {{\n"
    for d in all_domains():
        e = d.replace(".", r"\.")
        sni += f"    ^{e}$ *:443\n    .*\\.{e}$ *:443\n"
    sni += "    .* *:443\n}\n"
    write(SNI_CONF, sni); write(SNI_CONF_DIR, sni)
    enable_sniproxy()
    run(["systemctl","restart","dnsmasq"], True)
    run(["systemctl","restart","sniproxy"], True)

def enable_sniproxy():
    data = read(SNI_DEFAULT)
    if "ENABLED=" in data:
        data = "\n".join("ENABLED=1" if x.startswith("ENABLED=") else x for x in data.splitlines()) + "\n"
    else:
        data += "\nENABLED=1\n"
    write(SNI_DEFAULT, data)
    write(SNI_SYSTEMD_SERVICE, f"""[Unit]
Description=HTTPS SNI Proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/sbin/sniproxy -f -c {SNI_CONF}
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
""")
    run(["systemctl","daemon-reload"], True)

def check_ai(url):
    code = out(["curl","-k","-sS","-L","--connect-timeout","5","--max-time","10","-o","/dev/null","-w","%{http_code}",url])
    return code.startswith("2")

def auth_conf():
    parts = read(AUTH_FILE).strip().split(":")
    return parts if len(parts) == 3 else ["admin","",""]

def verify(user, password):
    u, salt, hv = auth_conf()
    if user != u or not salt or not hv: return False
    got = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 180000).hex()
    return hmac.compare_digest(got, hv)

def secret():
    s = read(SECRET_FILE).strip()
    if not s:
        s = secrets.token_hex(32); write(SECRET_FILE, s + "\n")
    return bytes.fromhex(s)

def token():
    t = read(TOKEN_FILE).strip()
    if not t:
        t = secrets.token_urlsafe(24); write(TOKEN_FILE, t + "\n")
    return t

def sign(data):
    return hmac.new(secret(), data.encode(), hashlib.sha256).hexdigest()

def esc(s): return html.escape(str(s), quote=True)

def now(): return int(time.time())

class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "AIUnlockPanel/1.0"

    def log_message(self, fmt, *args):
        return

    def send_html(self, body, code=200):
        raw = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def redirect(self, path):
        self.send_response(303); self.send_header("Location", path); self.end_headers()

    def form(self):
        ln = int(self.headers.get("Content-Length","0") or 0)
        data = self.rfile.read(ln).decode()
        return {k:v[0] for k,v in urllib.parse.parse_qs(data).items()}

    def cookie_sid(self):
        c = http.cookies.SimpleCookie(self.headers.get("Cookie",""))
        if "ai_unlock_session" not in c: return None
        val = c["ai_unlock_session"].value
        if "." not in val: return None
        sid, sig = val.split(".",1)
        if not hmac.compare_digest(sign(sid), sig): return None
        sess = SESSIONS.get(sid)
        if not sess or sess["exp"] < now(): return None
        return sid

    def need_auth(self):
        sid = self.cookie_sid()
        if sid: return sid
        self.redirect("/login"); return None

    def csrf_ok(self, sid, form):
        return hmac.compare_digest(SESSIONS.get(sid,{}).get("csrf",""), form.get("csrf",""))

    def layout(self, title, content, sid):
        csrf = SESSIONS[sid]["csrf"]
        return f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(title)} - AI Unlock</title><style>{CSS}</style></head><body><aside class="side"><div class="brand">AI Unlock</div><nav class="nav"><a href="/">仪表盘</a><a href="/nodes">节点管理</a><a href="/domains">域名池</a></nav><form class="logout" method="post" action="/logout"><input type="hidden" name="csrf" value="{csrf}"><button>退出登录</button></form></aside><main class="main"><header class="top"><h1>{esc(title)}</h1></header>{content}</main></body></html>"""

    def login_page(self, err=""):
        alert = f'<div class="alert bad">{esc(err)}</div>' if err else ""
        return f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>登录 - AI Unlock</title><style>{CSS}</style></head><body class="login"><form class="login-box" method="post" action="/login"><h1>AI Unlock</h1><p>登录管理面板</p>{alert}<label>用户名<input name="username" value="admin" autocomplete="username"></label><label>密码<input name="password" type="password" autocomplete="current-password" autofocus></label><button>登录</button></form></body></html>"""

    def flash(self, q):
        msg = q.get("ok", [""])[0] if "ok" in q else ""
        err = q.get("err", [""])[0] if "err" in q else ""
        maps = {"added":"已添加","saved":"已保存","deleted":"已删除","done":"操作完成","cleared":"已清空"}
        errs = {"csrf":"页面已过期，请刷新重试","bad_ip":"IP 格式错误","exists":"IP 已存在","bad_domain":"域名格式错误","save":"保存失败，请检查权限"}
        if msg: return f'<div class="alert ok">{esc(maps.get(msg,msg))}</div>'
        if err: return f'<div class="alert bad">{esc(errs.get(err,err))}</div>'
        return ""

    def do_GET(self):
        p = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(p.query)
        if p.path == "/login":
            if self.cookie_sid(): return self.redirect("/")
            return self.send_html(self.login_page())
        if p.path == "/node.sh":
            if q.get("token",[""])[0] != token():
                self.send_response(403); self.end_headers(); return
            ip = public_ip()
            body = f"""#!/bin/bash
set -e
[ "$EUID" -ne 0 ] && echo "请使用 root 权限运行" && exit 1
UNLOCK_IP="{ip}"
if command -v systemctl >/dev/null 2>&1 && systemctl is-active systemd-resolved >/dev/null 2>&1; then systemctl stop systemd-resolved 2>/dev/null || true; systemctl disable systemd-resolved 2>/dev/null || true; fi
chattr -i /etc/resolv.conf 2>/dev/null || true
rm -f /etc/resolv.conf
printf 'nameserver %s\\n' "$UNLOCK_IP" > /etc/resolv.conf
chattr +i /etc/resolv.conf 2>/dev/null || true
echo "节点机 DNS 已指向 $UNLOCK_IP"
"""
            raw = body.encode(); self.send_response(200); self.send_header("Content-Type","text/x-shellscript; charset=utf-8"); self.send_header("Content-Length",str(len(raw))); self.end_headers(); self.wfile.write(raw); return
        sid = self.need_auth()
        if not sid: return
        if p.path == "/":
            return self.send_html(self.layout("仪表盘", self.dashboard(q, sid), sid))
        if p.path == "/nodes":
            return self.send_html(self.layout("节点管理", self.nodes_page(q, sid), sid))
        if p.path == "/domains":
            return self.send_html(self.layout("域名池", self.domains_page(q, sid), sid))
        self.send_response(404); self.end_headers()

    def do_POST(self):
        p = urllib.parse.urlparse(self.path)
        if p.path == "/login":
            f = self.form(); ip = self.client_address[0]; rec = FAILS.get(ip, [0,0])
            if rec[0] >= 8 and now() - rec[1] < 600: return self.send_html(self.login_page("失败次数过多，请稍后再试"), 429)
            if verify(f.get("username",""), f.get("password","")):
                sid = secrets.token_urlsafe(32); SESSIONS[sid] = {"exp": now()+43200, "csrf": secrets.token_urlsafe(24)}
                cookie = f"ai_unlock_session={sid}.{sign(sid)}; Path=/; Max-Age=43200; HttpOnly; SameSite=Strict"
                self.send_response(303); self.send_header("Location","/"); self.send_header("Set-Cookie",cookie); self.end_headers(); return
            FAILS[ip] = [rec[0]+1, now()]
            return self.send_html(self.login_page("用户名或密码错误"), 401)
        sid = self.need_auth()
        if not sid: return
        f = self.form()
        if not self.csrf_ok(sid, f): return self.redirect("/?err=csrf")
        if p.path == "/logout":
            SESSIONS.pop(sid, None); self.send_response(303); self.send_header("Location","/login"); self.send_header("Set-Cookie","ai_unlock_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"); self.end_headers(); return
        if p.path.startswith("/nodes"): return self.nodes_post(p.path, f)
        if p.path.startswith("/domains"): return self.domains_post(p.path, f)
        if p.path.startswith("/action/"): return self.action_post(p.path)
        self.send_response(404); self.end_headers()

    def dashboard(self, q, sid):
        ip = public_ip(); nodes = load_nodes(); host = self.headers.get("Host", f"{ip}:8088")
        quick = f"curl -fsSL http://{host}/node.sh?token={urllib.parse.quote(token())} | bash"
        cards = f"""<section class="grid metrics"><div class="metric"><span>公网 IP</span><strong>{esc(ip)}</strong></div><div class="metric"><span>dnsmasq</span><strong class="{ 'ok' if service_status('dnsmasq')=='active' else 'bad'}">{service_status('dnsmasq')}</strong></div><div class="metric"><span>sniproxy</span><strong class="{ 'ok' if service_status('sniproxy')=='active' else 'bad'}">{service_status('sniproxy')}</strong></div><div class="metric"><span>白名单节点</span><strong>{len(nodes)}</strong></div></section>"""
        csrf = SESSIONS[sid]["csrf"]
        actions = f"""<section class="card"><div class="head"><div><h2>快捷操作</h2><p>规则、白名单和服务控制。</p></div></div><div class="actions"><form method="post" action="/action/update"><input type="hidden" name="csrf" value="{csrf}"><button>重新生成规则</button></form><form method="post" action="/action/sync"><input type="hidden" name="csrf" value="{csrf}"><button>同步白名单</button></form><form method="post" action="/action/stop"><input type="hidden" name="csrf" value="{csrf}"><button class="danger">暂停服务</button></form></div></section>"""
        quick_html = f"""<section class="card"><div class="head"><div><h2>节点机快速使用命令</h2><p>在节点机 root 终端执行。</p></div></div><pre class="cmd">{esc(quick)}</pre></section>"""
        checks = "".join(f'<div class="check"><span class="{ "ok" if check_ai(u) else "bad"}">{"通过" if check_ai(u) else "失败"}</span><strong>{esc(u)}</strong></div>' for u in AI_URLS)
        return self.flash(q) + cards + actions + quick_html + f'<section class="card"><div class="head"><div><h2>AI 访问测试</h2><p>只把 2xx 计为通过。</p></div></div><div class="checks">{checks}</div></section>'

    def nodes_page(self, q, sid):
        csrf = SESSIONS[sid]["csrf"]; nodes = load_nodes()
        rows = ""
        for n in nodes:
            rows += f"""<tr><td><code>{esc(n.get('ip',''))}</code></td><td><form class="inline" method="post" action="/nodes/edit"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="id" value="{esc(n.get('id',''))}"><input name="ip" value="{esc(n.get('ip',''))}"><input name="name" value="{esc(n.get('name',''))}" placeholder="名称"><input name="note" value="{esc(n.get('note',''))}" placeholder="备注"><button>保存</button></form></td><td class="muted">{esc(n.get('created',''))}</td><td><form method="post" action="/nodes/delete"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="id" value="{esc(n.get('id',''))}"><button class="ghost danger">删除</button></form></td></tr>"""
        return self.flash(q) + f"""<section class="grid split"><div class="card"><div class="head"><div><h2>添加节点</h2><p>添加后自动同步白名单。</p></div></div><form class="stack" method="post" action="/nodes/add"><input type="hidden" name="csrf" value="{csrf}"><label>节点公网 IP<input name="ip" required placeholder="1.2.3.4"></label><label>名称<input name="name"></label><label>备注<input name="note"></label><button>添加节点</button></form></div><div class="card"><div class="head"><div><h2>批量添加</h2><p>每行一个 IP，可跟名称。</p></div></div><form class="stack" method="post" action="/nodes/batch_add"><input type="hidden" name="csrf" value="{csrf}"><textarea name="items" rows="7" placeholder="1.2.3.4 节点A&#10;5.6.7.8 节点B"></textarea><button>批量添加</button></form></div></section><section class="card"><div class="head"><div><h2>节点列表</h2><p>共 {len(nodes)} 个。</p></div></div><div class="table"><table><thead><tr><th>IP</th><th>编辑</th><th>添加时间</th><th></th></tr></thead><tbody>{rows}</tbody></table></div></section><section class="card"><div class="head"><div><h2>批量删除</h2><p>输入要删除的 IP。</p></div></div><form class="stack" method="post" action="/nodes/batch_delete"><input type="hidden" name="csrf" value="{csrf}"><textarea name="items" rows="5"></textarea><button class="danger">批量删除</button></form></section>"""

    def nodes_post(self, path, f):
        nodes = load_nodes()
        if path == "/nodes/add":
            ip = f.get("ip","").strip()
            if not valid_ip(ip): return self.redirect("/nodes?err=bad_ip")
            if any(n.get("ip") == ip for n in nodes): return self.redirect("/nodes?err=exists")
            nodes.append({"id":secrets.token_hex(8),"ip":ip,"name":f.get("name","").strip(),"note":f.get("note","").strip(),"created":time.strftime("%Y-%m-%d %H:%M")})
        elif path == "/nodes/edit":
            ip = f.get("ip","").strip(); nid = f.get("id","")
            if not valid_ip(ip): return self.redirect("/nodes?err=bad_ip")
            if any(n.get("id") != nid and n.get("ip") == ip for n in nodes): return self.redirect("/nodes?err=exists")
            for n in nodes:
                if n.get("id") == nid:
                    n["ip"] = ip; n["name"] = f.get("name","").strip(); n["note"] = f.get("note","").strip()
        elif path == "/nodes/delete":
            nodes = [n for n in nodes if n.get("id") != f.get("id","")]
        elif path == "/nodes/batch_add":
            seen = {n.get("ip") for n in nodes}
            for line in f.get("items","").replace(","," ").splitlines():
                parts = line.split()
                if not parts: continue
                ip = parts[0]
                if valid_ip(ip) and ip not in seen:
                    nodes.append({"id":secrets.token_hex(8),"ip":ip,"name":" ".join(parts[1:]),"note":"","created":time.strftime("%Y-%m-%d %H:%M")}); seen.add(ip)
        elif path == "/nodes/batch_delete":
            ips = set(f.get("items","").replace(","," ").split())
            nodes = [n for n in nodes if n.get("ip") not in ips]
        save_nodes(nodes)
        return self.redirect("/nodes?ok=saved")

    def domains_page(self, q, sid):
        csrf = SESSIONS[sid]["csrf"]; custom = load_custom_domains()
        custom_html = "".join(f'<div class="domain"><code>{esc(d)}</code><form method="post" action="/domains/delete"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="domain" value="{esc(d)}"><button class="ghost danger">删除</button></form></div>' for d in custom) or '<p class="muted">暂无自定义域名</p>'
        pills = "".join(f'<span class="pill">{esc(d)}</span>' for d in BASE_DOMAINS)
        return self.flash(q) + f"""<section class="card"><div class="head"><div><h2>添加自定义域名</h2><p>保存后自动重新生成规则。</p></div></div><form class="row" method="post" action="/domains/add"><input type="hidden" name="csrf" value="{csrf}"><input name="domain" required placeholder="example.ai"><button>添加</button></form></section><section class="card"><div class="head"><div><h2>自定义域名池</h2><p>共 {len(custom)} 个。</p></div></div>{custom_html}<form method="post" action="/domains/clear"><input type="hidden" name="csrf" value="{csrf}"><button class="danger">清空自定义域名</button></form></section><section class="card"><div class="head"><div><h2>默认域名池</h2><p>内置只读。</p></div></div><div class="pills">{pills}</div></section>"""

    def domains_post(self, path, f):
        domains = load_custom_domains()
        if path == "/domains/add":
            d = clean_domain(f.get("domain",""))
            if not d: return self.redirect("/domains?err=bad_domain")
            if d not in domains: domains.append(d)
        elif path == "/domains/delete":
            domains = [d for d in domains if d != f.get("domain","")]
        elif path == "/domains/clear":
            domains = []
        save_custom_domains(domains)
        return self.redirect("/domains?ok=saved")

    def action_post(self, path):
        if path == "/action/update": update_rules()
        elif path == "/action/sync": sync_firewall(load_nodes())
        elif path == "/action/stop": run(["systemctl","stop","dnsmasq"], True); run(["systemctl","stop","sniproxy"], True)
        return self.redirect("/?ok=done")

def main():
    os.makedirs(BASE_DIR, exist_ok=True)
    port = int(read(PORT_FILE, "8088").strip() or "8088")
    with socketserver.ThreadingTCPServer(("0.0.0.0", port), Handler) as httpd:
        print(f"AI Unlock panel listening on 0.0.0.0:{port}", flush=True)
        httpd.serve_forever()

if __name__ == "__main__":
    main()
PYEOF
  chmod +x "$PANEL_SCRIPT"
}

set_panel_password() {
  local user="${1:-admin}" pass="$2"
  [ -z "$pass" ] && return 1
  python3 - "$PANEL_AUTH_FILE" "$user" "$pass" <<'PYEOF'
import hashlib, os, sys
path, user, password = sys.argv[1], sys.argv[2], sys.argv[3]
salt = os.urandom(16)
digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 180000).hex()
open(path, "w").write(f"{user}:{salt.hex()}:{digest}\n")
PYEOF
}

install_panel_service() {
  ensure_root
  ensure_base_dir
  if ! command_exists python3; then
    info "安装 Python3..."
    install_packages python3 || return 1
  fi

  local port pass show_ip
  port="$(panel_port)"
  read -r -p "Web 面板端口 [${port}]: " input_port
  [ -n "$input_port" ] && port="$input_port"
  if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then warn "端口无效。"; return 1; fi
  printf '%s\n' "$port" > "$PANEL_PORT_FILE"

  if [ ! -s "$PANEL_AUTH_FILE" ]; then
    pass="$(random_string 18)"
    set_panel_password "admin" "$pass" || return 1
  else
    read -r -p "是否重置 Web 面板 admin 密码？(y/N): " reset_pass
    if [ "$reset_pass" = "y" ] || [ "$reset_pass" = "Y" ]; then
      pass="$(random_string 18)"
      set_panel_password "admin" "$pass" || return 1
    fi
  fi

  [ -s "$PANEL_SECRET_FILE" ] || random_string 64 > "$PANEL_SECRET_FILE"
  [ -s "$PANEL_TOKEN_FILE" ] || random_string 32 > "$PANEL_TOKEN_FILE"
  write_panel_script

  cat > "$PANEL_SERVICE" <<EOF
[Unit]
Description=AI Unlock Web Panel
After=network-online.target dnsmasq.service sniproxy.service
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 $PANEL_SCRIPT
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

  if command_exists systemctl; then
    systemctl daemon-reload
    systemctl enable ai-unlock-panel.service >/dev/null 2>&1
    systemctl restart ai-unlock-panel.service
  fi

  show_ip="$(detect_public_ip)"
  ok "Web 面板已安装并启动。"
  printf "访问地址: http://%s:%s\n" "$show_ip" "$port"
  printf "用户名: admin\n"
  [ -n "$pass" ] && printf "初始密码: %s\n" "$pass"
}

panel_status() {
  local port show_ip
  port="$(panel_port)"
  show_ip="$(detect_public_ip)"
  printf "Web 面板服务: %s\n" "$(service_status ai-unlock-panel)"
  printf "访问地址: http://%s:%s\n" "$show_ip" "$port"
}

panel_logs() {
  if command_exists journalctl; then journalctl -u ai-unlock-panel --no-pager -n 80; else panel_status; fi
}

change_panel_port() {
  local old_port new_port
  old_port="$(panel_port)"
  read -r -p "输入新的 Web 面板端口 [当前 $old_port]: " new_port
  [ -z "$new_port" ] && return 0
  if ! [[ "$new_port" =~ ^[0-9]+$ ]] || [ "$new_port" -lt 1 ] || [ "$new_port" -gt 65535 ]; then warn "端口无效。"; return 1; fi
  printf '%s\n' "$new_port" > "$PANEL_PORT_FILE"
  service_restart ai-unlock-panel
  ok "端口已修改。"
  panel_status
}

reset_panel_password() {
  local pass
  pass="$(random_string 18)"
  set_panel_password "admin" "$pass" || return 1
  service_restart ai-unlock-panel
  ok "Web 面板密码已重置。"
  printf "用户名: admin\n新密码: %s\n" "$pass"
}

stop_panel_service() {
  service_stop ai-unlock-panel
  ok "Web 面板已停止。"
}

uninstall_panel_service() {
  if command_exists systemctl; then
    systemctl disable ai-unlock-panel.service 2>/dev/null || true
    systemctl stop ai-unlock-panel.service 2>/dev/null || true
    rm -f "$PANEL_SERVICE"
    systemctl daemon-reload 2>/dev/null || true
  fi
  rm -f "$PANEL_SCRIPT"
  ok "Web 面板已卸载，配置数据已保留。"
}

panel_menu() {
  while true; do
    clear
    printf "%b\n" "$(color 36 "======================================")"
    printf "%b\n" "$(color 36 "           Web 面板管理")"
    printf "%b\n" "$(color 36 "======================================")"
    printf "  %b 安装/更新 Web 面板\n" "$(color 32 "1.")"
    printf "  %b 查看面板状态\n" "$(color 32 "2.")"
    printf "  %b 查看面板日志\n" "$(color 32 "3.")"
    printf "  %b 修改面板端口\n" "$(color 32 "4.")"
    printf "  %b 重置登录密码\n" "$(color 32 "5.")"
    printf "  %b 停止面板\n" "$(color 32 "6.")"
    printf "  %b 卸载面板程序\n" "$(color 32 "7.")"
    printf "  %b 返回\n" "$(color 32 "0.")"
    printf "%b\n" "$(color 36 "======================================")"
    read -r -p "请选择 [0-7]: " choice
    case "$choice" in
      1) install_panel_service; pause ;;
      2) panel_status; pause ;;
      3) panel_logs; pause ;;
      4) change_panel_port; pause ;;
      5) reset_panel_password; pause ;;
      6) stop_panel_service; pause ;;
      7) uninstall_panel_service; pause ;;
      0) return ;;
      *) warn "无效选项"; sleep 1 ;;
    esac
  done
}

# ================= 核心环境安装/更新 =================
is_unlock_installed() { if [ -f "$DNSMASQ_CONF" ] && [ -f "$SNI_CONF" ]; then return 0; fi; return 1; }
confirm_reinstall_requested() { if ! is_unlock_installed; then return 0; fi; read -r -p "检测到已安装，覆盖重装更新配置？(y/N): " confirm; case "$confirm" in y|Y) return 0 ;; *) warn "已取消。"; return 1 ;; esac; }

sanitize_domain() { printf '%s' "$1" | sed -e 's#^[a-zA-Z][a-zA-Z0-9+.-]*://##' -e 's#^\\*\\.##' -e 's#/.*##' -e 's/:.*//'; }
write_custom_domains() { : > "$CUSTOM_DOMAIN_FILE"; for domain in "${CUSTOM_DOMAINS[@]}"; do printf '%s\n' "$domain" >> "$CUSTOM_DOMAIN_FILE"; done; }

load_custom_domains() {
  CUSTOM_DOMAINS=()
  [ -f "$CUSTOM_DOMAIN_FILE" ] || return 0
  while IFS= read -r line; do
    line="$(sanitize_domain "$line")"; [ -z "$line" ] && continue; case "$line" in \#*) continue ;; esac; CUSTOM_DOMAINS+=("$line")
  done < "$CUSTOM_DOMAIN_FILE"
}

collect_domains() {
  declare -A seen=()
  for domain in "${BASE_DOMAINS[@]}"; do domain="$(sanitize_domain "$domain")"; [ -z "$domain" ] && continue; if [ -z "${seen[$domain]+x}" ]; then seen["$domain"]=1; printf '%s\n' "$domain"; fi; done
  load_custom_domains
  for domain in "${CUSTOM_DOMAINS[@]}"; do domain="$(sanitize_domain "$domain")"; [ -z "$domain" ] && continue; if [ -z "${seen[$domain]+x}" ]; then seen["$domain"]=1; printf '%s\n' "$domain"; fi; done
}

escape_regex_domain() { printf '%s' "$1" | sed 's/\./\\./g'; }

update_rules() {
  ensure_base_dir; mkdir -p /etc/dnsmasq.d
  SERVER_IP="$(detect_public_ip)"
  info "生成分流配置..."
  {
    printf '# generated by ai_unlock installer\n'
    printf 'port=53\n'
    printf 'listen-address=0.0.0.0\n'
    printf 'bind-interfaces\n'
    printf 'no-resolv\n'
    for dns in "${PUBLIC_DNS_SERVERS[@]}"; do printf 'server=%s\n' "$dns"; done
    printf 'cache-size=10000\n'
    printf 'domain-needed\n'
    printf 'bogus-priv\n'
    while IFS= read -r domain; do
      [ -z "$domain" ] && continue
      printf 'local=/%s/\n' "$domain"
      printf 'address=/%s/%s\n' "$domain" "$SERVER_IP"
    done < <(collect_domains)
  } > "$DNSMASQ_CONF"
  
  # 智能判断 IPv6 环境：若系统有公网 IPv6 则双栈监听，否则只监听 IPv4 防止报错崩溃
  local listen_addr="0.0.0.0:443"
  if ip -6 addr show scope global 2>/dev/null | grep -q "inet6"; then
    listen_addr="443"
  fi

  {
    cat <<EOF
user daemon
pidfile /var/run/sniproxy.pid

error_log {
    syslog daemon
    priority notice
}

listen $listen_addr {
    proto tls
    table https_hosts
}

table https_hosts {
EOF
    while IFS= read -r domain; do [ -z "$domain" ] && continue; escaped="$(escape_regex_domain "$domain")"; printf '    ^%s$ *:443\n    .*\\.%s$ *:443\n' "$escaped" "$escaped"; done < <(collect_domains)
    printf '    .* *:443\n'
    printf '}\n'
  } > "$SNI_CONF"
  mkdir -p "$(dirname "$SNI_CONF_DIR")"
  cp -f "$SNI_CONF" "$SNI_CONF_DIR"

  # 重启时会触发前面的强杀逻辑，确保干干净净拉起新进程
  service_restart dnsmasq
  enable_sniproxy_default
  install_sniproxy_systemd_unit
  validate_sniproxy_config || return 1
  service_start sniproxy
  if [ "$(service_status sniproxy)" != "active" ]; then
    show_sniproxy_failure
    return 1
  fi
  ok "配置已更新并重启服务。"
}

install_unlock_core() {
  if ! confirm_reinstall_requested; then return 1; fi
  
  info "环境准备与清理..."
  backup_unlock_resolv_conf
  release_port_53
  release_port_443

  info "安装依赖组件..."
  install_packages dnsmasq sniproxy curl e2fsprogs iproute2 psmisc dnsutils || return 1
  install_firewall_tools || true
  firewall_init_backend || warn "未检测到可用防火墙后端。"

  enable_sniproxy_default
  install_sniproxy_systemd_unit
  service_enable dnsmasq; service_enable sniproxy
  update_rules
  setup_firewall_persistence
  
  show_unlock_summary
  ok "部署完成！请进入白名单管理添加节点 IP。"
}

uninstall_unlock_core() {
  read -r -p "确认彻底卸载并清理全部环境？(y/n): " confirm
  if [ "$confirm" = "y" ]; then
    info "正在清理服务与残留..."
    if command_exists systemctl; then
      systemctl disable ai-unlock-panel.service 2>/dev/null || true
      systemctl stop ai-unlock-panel.service 2>/dev/null || true
      rm -f "$PANEL_SERVICE"
      systemctl disable ai-unlock-firewall.service 2>/dev/null || true
      systemctl stop ai-unlock-firewall.service 2>/dev/null || true
      rm -f "$SYSTEMD_SERVICE"
      systemctl disable sniproxy.service 2>/dev/null || true
      systemctl stop sniproxy.service 2>/dev/null || true
      rm -f "$SNI_SYSTEMD_SERVICE"
      systemctl daemon-reload 2>/dev/null || true
    fi
    remove_firewall_rules
    restore_unlock_resolv_conf
    if command_exists systemctl; then systemctl enable systemd-resolved 2>/dev/null || true; systemctl start systemd-resolved 2>/dev/null || true; fi
    
    rm -rf "$BASE_DIR"
    rm -f "$DNSMASQ_CONF" "$SNI_CONF" "$PANEL_SCRIPT"
    
    service_stop dnsmasq
    service_stop sniproxy
    release_port_443
    
    ok "清理完毕，已恢复系统原生状态！"
  fi
}

# ================= DNS 辅助 =================
write_public_resolv_conf() {
  chattr -i /etc/resolv.conf 2>/dev/null || true; rm -f /etc/resolv.conf
  for dns in "${PUBLIC_DNS_SERVERS[@]}"; do printf 'nameserver %s\n' "$dns" >> /etc/resolv.conf; done
}

backup_resolv_conf() { ensure_base_dir; if [ ! -f "$RESOLV_BACKUP" ]; then cp -a /etc/resolv.conf "$RESOLV_BACKUP" 2>/dev/null || true; fi; }
restore_resolv_conf() {
  chattr -i /etc/resolv.conf 2>/dev/null || true
  write_public_resolv_conf
  ok "已恢复公共 DNS: ${PUBLIC_DNS_SERVERS[*]}"
}

backup_unlock_resolv_conf() { ensure_base_dir; if [ ! -f "$UNLOCK_RESOLV_BACKUP" ]; then cp -a /etc/resolv.conf "$UNLOCK_RESOLV_BACKUP" 2>/dev/null || true; fi; }
restore_unlock_resolv_conf() {
  chattr -i /etc/resolv.conf 2>/dev/null || true
  if [ -f "$UNLOCK_RESOLV_BACKUP" ]; then cp -a "$UNLOCK_RESOLV_BACKUP" /etc/resolv.conf 2>/dev/null || true; ok "已恢复原生 DNS。"
  else write_public_resolv_conf; fi
}

# ================= 菜单管理系统 =================
show_domain_pool() {
  load_custom_domains
  printf "\n%b\n" "$(color 36 "默认域名池")"
  local i=1; for d in "${BASE_DOMAINS[@]}"; do printf "  [%b] %s\n" "$(color 33 "$i")" "$d"; ((i++)); done
  
  printf "\n%b\n" "$(color 36 "自定义域名池")"
  if [ "${#CUSTOM_DOMAINS[@]}" -eq 0 ]; then echo "  暂无"; else 
    local j=1; for d in "${CUSTOM_DOMAINS[@]}"; do printf "  [%b] %s\n" "$(color 33 "$j")" "$d"; ((j++)); done
  fi
  echo ""
}

domain_menu() {
  while true; do
    clear
    printf "%b\n" "$(color 36 "======================================")"
    printf "%b\n" "$(color 36 "         域名池管理")"
    printf "%b\n" "$(color 36 "======================================")"
    printf "  %b 查看域名池\n" "$(color 32 "1.")"
    printf "  %b 添加自定义域名\n" "$(color 32 "2.")"
    printf "  %b 删除自定义域名\n" "$(color 32 "3.")"
    printf "  %b 清空自定义域名\n" "$(color 32 "4.")"
    printf "  %b 恢复默认配置\n" "$(color 32 "5.")"
    printf "  %b 返回\n" "$(color 32 "0.")"
    printf "%b\n" "$(color 36 "======================================")"
    read -r -p "请选择 [0-5]: " choice
    case "$choice" in
      1) show_domain_pool; pause ;;
      2) read -r -p "输入要添加的域名: " d; d="$(sanitize_domain "$d")"; if [ -n "$d" ]; then load_custom_domains; CUSTOM_DOMAINS+=("$d"); write_custom_domains; ok "已添加 $d"; update_rules; fi; pause ;;
      3) 
         load_custom_domains
         if [ "${#CUSTOM_DOMAINS[@]}" -eq 0 ]; then warn "无自定义域名。"; pause; continue; fi
         show_domain_pool; read -r -p "输入要删除的序号: " idx
         if [[ "$idx" =~ ^[0-9]+$ ]] && [ "$idx" -ge 1 ] && [ "$idx" -le "${#CUSTOM_DOMAINS[@]}" ]; then
           local del_d="${CUSTOM_DOMAINS[$((idx - 1))]}"; local nx=(); for d in "${CUSTOM_DOMAINS[@]}"; do if [ "$d" != "$del_d" ]; then nx+=("$d"); fi; done
           CUSTOM_DOMAINS=("${nx[@]}"); write_custom_domains; ok "已删除: $del_d"; update_rules
         else warn "序号无效。"; fi; pause ;;
      4) CUSTOM_DOMAINS=(); write_custom_domains; ok "已清空"; update_rules; pause ;;
      5) : > "$CUSTOM_DOMAIN_FILE"; ok "已恢复默认"; update_rules; pause ;;
      0) return ;;
      *) warn "无效选项"; sleep 1 ;;
    esac
  done
}

list_firewall_whitelist() {
  firewall_init_backend || return 1
  load_node_whitelist
  printf "防火墙后端: %s\n" "$FIREWALL_BACKEND"
  if [ "${#NODE_WHITELIST_IPS[@]}" -eq 0 ]; then printf "  暂无节点 IP\n"; else
    local i=1; for ip in "${NODE_WHITELIST_IPS[@]}"; do printf "  [%b] %s\n" "$(color 33 "$i")" "$ip"; ((i++)); done
  fi
}

firewall_menu() {
  while true; do
    clear
    printf "%b\n" "$(color 36 "======================================")"
    printf "%b\n" "$(color 36 "         白名单管理")"
    printf "%b\n" "$(color 36 "======================================")"
    printf "  %b 查看白名单\n" "$(color 32 "1.")"
    printf "  %b 添加单个 IP\n" "$(color 32 "2.")"
    printf "  %b 批量添加 IP\n" "$(color 32 "3.")"
    printf "  %b 删除节点 IP\n" "$(color 32 "4.")"
    printf "  %b 清空白名单\n" "$(color 32 "5.")"
    printf "  %b 返回\n" "$(color 32 "0.")"
    printf "%b\n" "$(color 36 "======================================")"
    read -r -p "请选择 [0-5]: " choice
    case "$choice" in
      1) list_firewall_whitelist; echo ""; pause ;;
      2) read -r -p "输入要放行的 IP: " ip; if ! validate_ipv4 "$ip"; then warn "IP 格式错误。"; else load_node_whitelist; local exists=0; for item in "${NODE_WHITELIST_IPS[@]}"; do if [ "$item" = "$ip" ]; then exists=1; break; fi; done; if [ "$exists" -eq 1 ]; then warn "IP 已存在。"; else NODE_WHITELIST_IPS+=("$ip"); save_node_whitelist; sync_firewall_whitelist; fi; fi; pause ;;
      3) read -r -p "输入多个 IP(用空格或逗号分隔): " list; list="$(printf '%s' "$list" | tr ',' ' ')"; load_node_whitelist; for ip in $list; do validate_ipv4 "$ip" || continue; local exists=0; for item in "${NODE_WHITELIST_IPS[@]}"; do if [ "$item" = "$ip" ]; then exists=1; break; fi; done; if [ "$exists" -eq 0 ]; then NODE_WHITELIST_IPS+=("$ip"); ok "已加入 $ip"; fi; done; save_node_whitelist; sync_firewall_whitelist; pause ;;
      4) 
         load_node_whitelist
         if [ "${#NODE_WHITELIST_IPS[@]}" -eq 0 ]; then warn "当前没有白名单。"; pause; continue; fi
         list_firewall_whitelist; echo ""
         read -r -p "请输入序号删除: " idx
         if [[ "$idx" =~ ^[0-9]+$ ]] && [ "$idx" -ge 1 ] && [ "$idx" -le "${#NODE_WHITELIST_IPS[@]}" ]; then
           local del_ip="${NODE_WHITELIST_IPS[$((idx - 1))]}"; local next=()
           for ip in "${NODE_WHITELIST_IPS[@]}"; do if [ "$ip" != "$del_ip" ]; then next+=("$ip"); fi; done
           NODE_WHITELIST_IPS=("${next[@]}"); save_node_whitelist; sync_firewall_whitelist; ok "已成功删除: $del_ip"
         else warn "输入序号无效。"; fi; pause ;;
      5) read -r -p "确认清空白名单？(y/n): " confirm; if [ "$confirm" = "y" ]; then NODE_WHITELIST_IPS=(); save_node_whitelist; sync_firewall_whitelist; ok "已清空"; fi; pause ;;
      0) return ;;
      *) warn "无效选项"; sleep 1 ;;
    esac
  done
}

# ================= 节点机功能核心 =================
set_node_dns() {
  read -r -p "输入【解锁机】公网 IP: " unlock_ip
  if [ -z "$unlock_ip" ]; then warn "不能为空。"; return; fi
  backup_resolv_conf
  if command_exists systemctl && systemctl is-active systemd-resolved >/dev/null 2>&1; then
    systemctl stop systemd-resolved 2>/dev/null || true
    systemctl disable systemd-resolved 2>/dev/null || true
  fi
  chattr -i /etc/resolv.conf 2>/dev/null || true
  rm -f /etc/resolv.conf
  printf 'nameserver %s\n' "$unlock_ip" > /etc/resolv.conf
  chattr +i /etc/resolv.conf 2>/dev/null || true
  ok "已设置 DNS: $unlock_ip"
  info "普通域名会由解锁机 dnsmasq 转发到公共 DNS；AI 域名会解析到解锁机。"
}

test_node_dns() {
  local configured_dns="$(awk '/^nameserver/ {print $2; exit}' /etc/resolv.conf)"
  if [ -z "$configured_dns" ]; then warn "未配置 DNS！"; return; fi
  local node_public_ip="$(detect_node_public_ip)"
  
  info "当前设定 DNS: $configured_dns"
  echo "--------------------------------------"
  info "系统 DNS 配置:"
  ls -l /etc/resolv.conf 2>/dev/null || true
  cat /etc/resolv.conf 2>/dev/null || true
  if command_exists resolvectl; then
    resolvectl status 2>/dev/null | sed -n '1,35p' || true
  fi
  if [ -n "$node_public_ip" ]; then
    info "当前节点公网 IP: $node_public_ip（解锁机白名单必须添加这个 IP）"
  else
    warn "未能自动获取节点公网 IP；请手动确认解锁机白名单里添加的是节点公网 IP。"
  fi
  info "将直接向 $configured_dns 发起 DNS 查询，避免被系统备用 DNS 干扰。"
  echo "--------------------------------------"
  info "分流解析状态:"

  local dns_ok_count=0 dns_miss_count=0 dns_timeout_count=0
  for domain in "chatgpt.com" "claude.ai" "gemini.google.com" "perplexity.ai"; do
    local resolved=""
    if command_exists dig; then resolved="$(dig @"$configured_dns" "$domain" A +time=3 +tries=1 +short 2>/dev/null | awk '/^[0-9]+\./ {print; exit}')"; fi
    if [ -z "$resolved" ] && command_exists nslookup; then resolved="$(nslookup -type=A "$domain" "$configured_dns" 2>/dev/null | awk '/^Address: / {print $2}' | grep -E '^[0-9]+\.' | tail -n 1)"; fi
    if [ -z "$resolved" ] && command_exists ping; then resolved="$(ping -c 1 -W 1 "$domain" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n 1)"; fi

    if [ -n "$resolved" ]; then
      if [ "$resolved" = "$configured_dns" ]; then dns_ok_count=$((dns_ok_count + 1)); printf "  %b %s -> %s\n" "$(color 32 "[成功]")" "$domain" "$resolved"
      else dns_miss_count=$((dns_miss_count + 1)); printf "  %b %s -> %s（未命中解锁机）\n" "$(color 31 "[失败]")" "$domain" "$resolved"; fi
    else dns_timeout_count=$((dns_timeout_count + 1)); printf "  %b %s -> 无 A 记录响应\n" "$(color 33 "[无响应]")" "$domain"; fi
  done
  if [ "$dns_ok_count" -eq 0 ] && [ "$dns_timeout_count" -gt 0 ]; then
    warn "AI 域名 A 记录无响应：请在解锁机白名单添加【节点机公网 IP】，并在云服务商安全组放行 UDP/TCP 53。"
    [ -n "$node_public_ip" ] && warn "当前节点公网 IP 是 $node_public_ip，请确认它已经在解锁机白名单中。"
  elif [ "$dns_miss_count" -gt 0 ]; then
    warn "AI 域名没有解析到解锁机：请在解锁机重新生成配置，并确认 dnsmasq 配置里有 local=/域名/ 和 address=/域名/$configured_dns。"
  fi

  echo "--------------------------------------"
  info "系统解析测试:"
  if command_exists getent; then
    if getent ahostsv4 example.com >/tmp/ai_unlock_getent_example.log 2>/dev/null; then
      printf "  %b getent example.com -> %s\n" "$(color 32 "[成功]")" "$(head -n 1 /tmp/ai_unlock_getent_example.log)"
    else
      printf "  %b getent example.com -> 失败\n" "$(color 31 "[失败]")"
    fi
    if getent ahostsv4 chatgpt.com >/tmp/ai_unlock_getent_chatgpt.log 2>/dev/null; then
      printf "  %b getent chatgpt.com -> %s\n" "$(color 32 "[成功]")" "$(head -n 1 /tmp/ai_unlock_getent_chatgpt.log)"
    else
      printf "  %b getent chatgpt.com -> 失败\n" "$(color 31 "[失败]")"
    fi
  else
    printf "  %b 未安装 getent，跳过系统解析测试\n" "$(color 33 "[跳过]")"
  fi

  echo "--------------------------------------"
  info "强制走解锁机测试:"
  
  for url in "${AI_CHECK_URLS[@]}"; do
    local host code
    host="$(echo "$url" | awk -F/ '{print $3}')"
    code="$(curl -k -sS -L --connect-timeout 5 --max-time 10 --resolve "${host}:443:${configured_dns}" -o /dev/null -w '%{http_code}' "$url" 2>/dev/null || true)"
    print_ai_http_result "解锁" "$url" "$code"
  done
}

unlock_menu() {
  while true; do
    clear
    printf "%b\n" "$(color 36 "======================================")"
    printf "%b\n" "$(color 36 "           部署解锁机")"
    printf "%b\n" "$(color 36 "======================================")"
    printf "  %b 安装\n" "$(color 32 "1.")"
    printf "  %b 运行状态检测\n" "$(color 32 "2.")"
    printf "  %b 查看服务日志\n" "$(color 32 "3.")"
    printf "  %b 重启服务\n" "$(color 32 "4.")"
    printf "  %b 暂停服务\n" "$(color 32 "5.")"
    printf "  %b 域名池管理\n" "$(color 32 "6.")"
    printf "  %b 白名单管理\n" "$(color 32 "7.")"
    printf "  %b Web 面板管理\n" "$(color 32 "8.")"
    printf "  %b 彻底卸载清理\n" "$(color 32 "9.")"
    printf "  %b 返回主菜单\n" "$(color 32 "0.")"
    printf "%b\n" "$(color 36 "======================================")"
    read -r -p "请选择 [0-9]: " choice
    case "$choice" in
      1) install_unlock_core; pause ;;
      2) show_unlock_summary; pause ;;
      3) show_unlock_logs; pause ;;
      4) restart_unlock_services; pause ;;
      5) stop_unlock_services; pause ;;
      6) domain_menu ;;
      7) firewall_menu ;;
      8) panel_menu ;;
      9) uninstall_unlock_core; pause ;;
      0) return ;;
      *) warn "无效选项"; sleep 1 ;;
    esac
  done
}

node_menu() {
  while true; do
    clear
    printf "%b\n" "$(color 36 "======================================")"
    printf "%b\n" "$(color 36 "           配置节点机")"
    printf "%b\n" "$(color 36 "======================================")"
    printf "  %b 指向解锁机 DNS\n" "$(color 32 "1.")"
    printf "  %b 恢复原生 DNS\n" "$(color 32 "2.")"
    printf "  %b 分流诊断与测试\n" "$(color 32 "3.")"
    printf "  %b 查看当前 DNS\n" "$(color 32 "4.")"
    printf "  %b 返回主菜单\n" "$(color 32 "0.")"
    printf "%b\n" "$(color 36 "======================================")"
    read -r -p "请选择 [0-4]: " choice
    case "$choice" in
      1) set_node_dns; pause ;;
      2) restore_resolv_conf; pause ;;
      3) test_node_dns; pause ;;
      4) printf "\n%b\n" "$(color 36 "/etc/resolv.conf")"; cat /etc/resolv.conf 2>/dev/null || true; pause ;;
      0) return ;;
      *) warn "无效选项"; sleep 1 ;;
    esac
  done
}

main_menu() {
  while true; do
    clear
    printf "%b\n" "$(color 36 "======================================")"
    printf "%b\n" "$(color 36 "         AI DNS 分流管理系统")"
    printf "%b\n" "$(color 36 "======================================")"
    printf "  %b 进入【解锁机】面板\n" "$(color 32 "1.")"
    printf "  %b 进入【节点机】面板\n" "$(color 32 "2.")"
    printf "  %b 退出\n" "$(color 32 "0.")"
    printf "%b\n" "$(color 36 "======================================")"
    read -r -p "请选择 [0-2]: " choice
    case "$choice" in
      1) unlock_menu ;;
      2) node_menu ;;
      0) exit 0 ;;
      *) warn "无效选项"; sleep 1 ;;
    esac
  done
}

main() {
  if [ "$1" = "sync-firewall" ]; then ensure_root; sync_firewall_whitelist >/dev/null 2>&1; exit 0; fi
  ensure_root
  ensure_base_dir
  main_menu
}

main "$@"
