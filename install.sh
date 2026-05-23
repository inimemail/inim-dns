#!/bin/bash

set -o pipefail

BASE_DIR="/etc/ai_unlock"
CUSTOM_DOMAIN_FILE="$BASE_DIR/custom_domains.conf"
NODE_WHITELIST_FILE="$BASE_DIR/node_whitelist.conf"
DNSMASQ_CONF="/etc/dnsmasq.d/ai_unlock.conf"
SNI_CONF="/etc/sniproxy.conf"
RESOLV_BACKUP="$BASE_DIR/resolv.conf.bak"
UNLOCK_RESOLV_BACKUP="$BASE_DIR/unlock-resolv.conf.bak"
FIREWALL_CHAIN="AI_UNLOCK_DNS"
SYNC_SCRIPT="$BASE_DIR/sync_firewall.sh"
SYSTEMD_SERVICE="/etc/systemd/system/ai-unlock-firewall.service"

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
    nft add rule inet ai_unlock input ip protocol udp udp dport 53 ip saddr @node_whitelist accept 2>/dev/null || true
    nft add rule inet ai_unlock input ip protocol tcp tcp dport 53 ip saddr @node_whitelist accept 2>/dev/null || true
    nft add rule inet ai_unlock input ip protocol udp udp dport 53 drop 2>/dev/null || true
    nft add rule inet ai_unlock input ip protocol tcp tcp dport 53 drop 2>/dev/null || true
    return 0
  fi
  if [ "$FIREWALL_BACKEND" = "iptables" ]; then
    if ! iptables -nL "$FIREWALL_CHAIN" >/dev/null 2>&1; then iptables -N "$FIREWALL_CHAIN" 2>/dev/null || true; iptables -A "$FIREWALL_CHAIN" -j DROP 2>/dev/null || true; fi
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
  nft flush set inet ai_unlock node_whitelist 2>/dev/null || true
  [ -f "$NODE_WHITELIST_FILE" ] || exit 0
  while IFS= read -r ip; do [[ -z "$ip" || "$ip" == \#* ]] && continue; nft add element inet ai_unlock node_whitelist "{ $ip }" 2>/dev/null || true; done < "$NODE_WHITELIST_FILE"
elif command -v iptables >/dev/null 2>&1 && iptables -nL "$FIREWALL_CHAIN" >/dev/null 2>&1; then
  iptables -F "$FIREWALL_CHAIN" 2>/dev/null || true
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
check_ai_endpoint() {
  local url="$1" code
  code="$(curl -k -sS -L --connect-timeout 5 --max-time 10 -o /dev/null -w '%{http_code}' "$url" 2>/dev/null || true)"
  if [ -n "$code" ] && [ "$code" != "000" ]; then printf "  [OK]   %s -> HTTP %s\n" "$url" "$code"; return 0; fi
  printf "  [FAIL] %s\n" "$url"
  return 1
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
    info "提示：若反复失败，可在主菜单选择 [1. 安装/更新环境] 触发强制大清场。"
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
  { printf '# generated by ai_unlock installer\n'; while IFS= read -r domain; do [ -z "$domain" ] && continue; printf 'address=/%s/%s\n' "$domain" "$SERVER_IP"; done < <(collect_domains); } > "$DNSMASQ_CONF"
  {
    cat <<'EOF'
user daemon
pidfile /var/run/sniproxy.pid
listen 443 { proto tls; table https_hosts; fallback reject; }
table https_hosts {
EOF
    while IFS= read -r domain; do [ -z "$domain" ] && continue; escaped="$(escape_regex_domain "$domain")"; printf '    ^%s$ *\n    .*\\.%s$ *\n' "$escaped" "$escaped"; done < <(collect_domains)
    printf '}\n'
  } > "$SNI_CONF"

  # 重启时会触发前面的强杀逻辑
  service_restart dnsmasq
  service_start sniproxy
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
      systemctl disable ai-unlock-firewall.service 2>/dev/null || true
      systemctl stop ai-unlock-firewall.service 2>/dev/null || true
      rm -f "$SYSTEMD_SERVICE"
      systemctl daemon-reload 2>/dev/null || true
    fi
    remove_firewall_rules
    restore_unlock_resolv_conf
    if command_exists systemctl; then systemctl enable systemd-resolved 2>/dev/null || true; systemctl start systemd-resolved 2>/dev/null || true; fi
    
    rm -rf "$BASE_DIR"
    rm -f "$DNSMASQ_CONF" "$SNI_CONF"
    
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
  if [ -f "$RESOLV_BACKUP" ]; then cp -f "$RESOLV_BACKUP" /etc/resolv.conf; ok "已恢复原生 DNS。"
  else warn "未找到备份，重置为公共 DNS。"; write_public_resolv_conf; fi
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
    printf "  %b 删除自定义域名 (按序号)\n" "$(color 32 "3.")"
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
    printf "  %b 批量添加 IP (空格或逗号分隔)\n" "$(color 32 "3.")"
    printf "  %b 删除节点 IP (按序号)\n" "$(color 32 "4.")"
    printf "  %b 清空白名单\n" "$(color 32 "5.")"
    printf "  %b 返回\n" "$(color 32 "0.")"
    printf "%b\n" "$(color 36 "======================================")"
    read -r -p "请选择 [0-5]: " choice
    case "$choice" in
      1) list_firewall_whitelist; echo ""; pause ;;
      2) read -r -p "输入要放行的 IP: " ip; if ! validate_ipv4 "$ip"; then warn "IP 格式错误。"; else load_node_whitelist; local exists=0; for item in "${NODE_WHITELIST_IPS[@]}"; do if [ "$item" = "$ip" ]; then exists=1; break; fi; done; if [ "$exists" -eq 1 ]; then warn "IP 已存在。"; else NODE_WHITELIST_IPS+=("$ip"); save_node_whitelist; sync_firewall_whitelist; fi; fi; pause ;;
      3) read -r -p "输入多个 IP: " list; list="$(printf '%s' "$list" | tr ',' ' ')"; load_node_whitelist; for ip in $list; do validate_ipv4 "$ip" || continue; local exists=0; for item in "${NODE_WHITELIST_IPS[@]}"; do if [ "$item" = "$ip" ]; then exists=1; break; fi; done; if [ "$exists" -eq 0 ]; then NODE_WHITELIST_IPS+=("$ip"); ok "已加入 $ip"; fi; done; save_node_whitelist; sync_firewall_whitelist; pause ;;
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
  chattr -i /etc/resolv.conf 2>/dev/null || true
  { printf 'nameserver %s\n' "$unlock_ip"; } > /etc/resolv.conf
  chattr +i /etc/resolv.conf 2>/dev/null || true
  ok "已指向: $unlock_ip (备用 DNS 已屏蔽)"
}

test_node_dns() {
  local configured_dns="$(awk '/^nameserver/ {print $2; exit}' /etc/resolv.conf)"
  if [ -z "$configured_dns" ]; then warn "未配置 DNS！"; return; fi
  
  info "当前设定 DNS: $configured_dns"
  echo "--------------------------------------"
  info "分流解析状态:"

  for domain in "chatgpt.com" "claude.ai" "gemini.google.com" "perplexity.ai"; do
    local resolved=""
    if command_exists nslookup; then resolved="$(nslookup "$domain" 2>/dev/null | grep -A1 "Name:" | grep "Address:" | awk '{print $2}' | head -n 1)"; fi
    if [ -z "$resolved" ] && command_exists ping; then resolved="$(ping -c 1 -W 1 "$domain" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n 1)"; fi

    if [ -n "$resolved" ]; then
      if [ "$resolved" = "$configured_dns" ]; then printf "  %b %s -> %s\n" "$(color 32 "[成功]")" "$domain" "$resolved"
      else printf "  %b %s -> %s\n" "$(color 31 "[失败]")" "$domain" "$resolved"; fi
    else printf "  %b %s -> 超时 (请检查白名单/安全组)\n" "$(color 33 "[超时]")" "$domain"; fi
  done

  echo "--------------------------------------"
  info "免 DNS 强制穿透连通性测试:"
  
  for url in "${AI_CHECK_URLS[@]}"; do
    local host code
    host="$(echo "$url" | awk -F/ '{print $3}')"
    code="$(curl -k -sS -L --connect-timeout 5 --max-time 10 --resolve "${host}:443:${configured_dns}" -o /dev/null -w '%{http_code}' "$url" 2>/dev/null || true)"
    if [ -n "$code" ] && [ "$code" != "000" ]; then printf "  %b %s -> HTTP %s\n" "$(color 32 "[通畅]")" "$url" "$code"
    else printf "  %b %s -> 阻断或超时\n" "$(color 31 "[阻断]")" "$url"; fi
  done
}

unlock_menu() {
  while true; do
    clear
    printf "%b\n" "$(color 36 "======================================")"
    printf "%b\n" "$(color 36 "           部署解锁机")"
    printf "%b\n" "$(color 36 "======================================")"
    printf "  %b 安装/更新环境\n" "$(color 32 "1.")"
    printf "  %b 运行状态检测\n" "$(color 32 "2.")"
    printf "  %b 域名池管理\n" "$(color 32 "3.")"
    printf "  %b 白名单管理\n" "$(color 32 "4.")"
    printf "  %b 彻底卸载清理\n" "$(color 32 "5.")"
    printf "  %b 返回主菜单\n" "$(color 32 "0.")"
    printf "%b\n" "$(color 36 "======================================")"
    read -r -p "请选择 [0-5]: " choice
    case "$choice" in
      1) install_unlock_core; pause ;;
      2) show_unlock_summary; pause ;;
      3) domain_menu ;;
      4) firewall_menu ;;
      5) uninstall_unlock_core; pause ;;
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
