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
  "https://openai.com"
  "https://claude.ai"
  "https://gemini.google.com"
  "https://copilot.microsoft.com"
  "https://perplexity.ai"
  "https://grok.com"
)

PUBLIC_DNS_SERVERS=(
  "1.1.1.1"
  "8.8.8.8"
)

OPENAI_DOMAINS=(
  "openai.com"
  "chatgpt.com"
  "oaiusercontent.com"
  "oaistatic.com"
)

ANTHROPIC_DOMAINS=(
  "anthropic.com"
  "claude.ai"
  "claude.com"
  "claudeusercontent.com"
)

GOOGLE_DOMAINS=(
  "google.com"
  "googleapis.com"
  "gstatic.com"
  "googleusercontent.com"
  "ggpht.com"
  "ytimg.com"
  "withgoogle.com"
  "googletagmanager.com"
  "googlevideo.com"
  "gemini.google.com"
  "aistudio.google.com"
)

PERPLEXITY_DOMAINS=(
  "perplexity.ai"
  "perplexity.com"
)

XAI_DOMAINS=(
  "x.ai"
  "grok.com"
  "api.x.ai"
)

MICROSOFT_DOMAINS=(
  "copilot.microsoft.com"
  "bing.com"
)

MIDJOURNEY_DOMAINS=(
  "midjourney.com"
  "alpha.midjourney.com"
)

DEEPSEEK_DOMAINS=(
  "deepseek.com"
  "chat.deepseek.com"
  "api.deepseek.com"
  "platform.deepseek.com"
)

MISTRAL_DOMAINS=(
  "mistral.ai"
  "chat.mistral.ai"
  "console.mistral.ai"
  "api.mistral.ai"
)

OTHER_DOMAINS=(
  "character.ai"
  "poe.com"
  "openrouter.ai"
  "platform.openrouter.ai"
  "meta.ai"
  "you.com"
)

BASE_DOMAINS=(
  "${OPENAI_DOMAINS[@]}"
  "${ANTHROPIC_DOMAINS[@]}"
  "${GOOGLE_DOMAINS[@]}"
  "${PERPLEXITY_DOMAINS[@]}"
  "${XAI_DOMAINS[@]}"
  "${MICROSOFT_DOMAINS[@]}"
  "${MIDJOURNEY_DOMAINS[@]}"
  "${DEEPSEEK_DOMAINS[@]}"
  "${MISTRAL_DOMAINS[@]}"
  "${OTHER_DOMAINS[@]}"
)

SERVER_IP=""
FIREWALL_BACKEND=""
NODE_WHITELIST_IPS=()

color() {
  printf "\033[%sm%s\033[0m" "$1" "$2"
}

info() {
  printf "%b\n" "$(color 36 "ℹ️  $*")"
}

ok() {
  printf "%b\n" "$(color 32 "✅ $*")"
}

warn() {
  printf "%b\n" "$(color 33 "⚠️  $*")"
}

err() {
  printf "%b\n" "$(color 31 "❌ $*")"
}

pause() {
  read -n 1 -s -r -p "按任意键继续..."
  printf "\n"
}

ensure_root() {
  if [ "$EUID" -ne 0 ]; then
    err "请使用 root 权限运行此脚本。"
    exit 1
  fi
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

ensure_base_dir() {
  mkdir -p "$BASE_DIR"
  touch "$CUSTOM_DOMAIN_FILE"
  touch "$NODE_WHITELIST_FILE"
}

detect_public_ip() {
  if [ -n "$SERVER_IP" ]; then
    printf '%s\n' "$SERVER_IP"
    return
  fi

  SERVER_IP="$(curl -fs4 --max-time 5 https://ifconfig.me 2>/dev/null || true)"
  if [ -z "$SERVER_IP" ] && command_exists hostname; then
    SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
  fi

  if [ -z "$SERVER_IP" ]; then
    read -r -p "请输入解锁机公网 IP: " SERVER_IP
  fi

  printf '%s\n' "$SERVER_IP"
}

install_packages() {
  local packages=("$@")

  if command_exists apt-get; then
    apt-get update -y
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}"
  elif command_exists dnf; then
    dnf install -y "${packages[@]}"
  elif command_exists yum; then
    yum install -y "${packages[@]}"
  elif command_exists pacman; then
    pacman -Sy --noconfirm "${packages[@]}"
  elif command_exists zypper; then
    zypper --non-interactive install -y "${packages[@]}"
  elif command_exists apk; then
    apk add --no-cache "${packages[@]}"
  else
    err "未找到可用的包管理器。"
    return 1
  fi
}

install_firewall_tools() {
  firewall_backend_ready && return 0

  if command_exists apt-get; then
    install_packages nftables iptables || true
  elif command_exists dnf || command_exists yum; then
    install_packages nftables iptables || true
  elif command_exists pacman; then
    install_packages nftables iptables || true
  elif command_exists zypper; then
    install_packages nftables iptables || true
  elif command_exists apk; then
    install_packages nftables iptables || true
  fi

  firewall_backend_ready
}

service_restart() {
  local svc="$1"
  if command_exists systemctl; then
    systemctl restart "$svc"
  elif command_exists service; then
    service "$svc" restart
  fi
}

service_enable() {
  local svc="$1"
  if command_exists systemctl; then
    systemctl enable "$svc" >/dev/null 2>&1
  fi
}

service_start() {
  local svc="$1"
  if command_exists systemctl; then
    systemctl start "$svc"
  elif command_exists service; then
    service "$svc" start
  fi
}

service_stop() {
  local svc="$1"
  if command_exists systemctl; then
    systemctl stop "$svc" >/dev/null 2>&1 || true
  elif command_exists service; then
    service "$svc" stop >/dev/null 2>&1 || true
  fi
}

service_status() {
  local svc="$1"
  if command_exists systemctl; then
    systemctl is-active "$svc" >/dev/null 2>&1 && echo "active" || echo "inactive"
  else
    echo "unknown"
  fi
}

firewall_detect_backend() {
  if command_exists nft; then
    echo "nftables"
    return
  fi

  if command_exists iptables; then
    echo "iptables"
    return
  fi

  echo "none"
}

firewall_init_backend() {
  FIREWALL_BACKEND="$(firewall_detect_backend)"
  if [ "$FIREWALL_BACKEND" = "nftables" ]; then
    if ! nft list table inet ai_unlock >/dev/null 2>&1; then
      nft add table inet ai_unlock
    fi
    if nft list chain inet ai_unlock input >/dev/null 2>&1; then
      nft flush chain inet ai_unlock input
    else
      nft add chain inet ai_unlock input '{ type filter hook input priority 0; policy accept; }'
    fi
    if ! nft list set inet ai_unlock node_whitelist >/dev/null 2>&1; then
      nft add set inet ai_unlock node_whitelist '{ type ipv4_addr; flags interval; }'
    fi
    nft add rule inet ai_unlock input ip protocol udp udp dport 53 ip saddr @node_whitelist accept
    nft add rule inet ai_unlock input ip protocol tcp tcp dport 53 ip saddr @node_whitelist accept
    nft add rule inet ai_unlock input ip protocol udp udp dport 53 drop
    nft add rule inet ai_unlock input ip protocol tcp tcp dport 53 drop
    return 0
  fi

  if [ "$FIREWALL_BACKEND" = "iptables" ]; then
    if ! iptables -nL "$FIREWALL_CHAIN" >/dev/null 2>&1; then
      iptables -N "$FIREWALL_CHAIN" 2>/dev/null || true
      iptables -A "$FIREWALL_CHAIN" -j DROP 2>/dev/null || true
    fi
    iptables -C INPUT -p udp --dport 53 -j "$FIREWALL_CHAIN" 2>/dev/null || iptables -I INPUT -p udp --dport 53 -j "$FIREWALL_CHAIN" 2>/dev/null || true
    iptables -C INPUT -p tcp --dport 53 -j "$FIREWALL_CHAIN" 2>/dev/null || iptables -I INPUT -p tcp --dport 53 -j "$FIREWALL_CHAIN" 2>/dev/null || true
    return 0
  fi

  return 1
}

firewall_backend_ready() {
  [ "$(firewall_detect_backend)" != "none" ]
}

load_node_whitelist() {
  NODE_WHITELIST_IPS=()
  [ -f "$NODE_WHITELIST_FILE" ] || return 0

  while IFS= read -r line; do
    line="$(sanitize_domain "$line")"
    [ -z "$line" ] && continue
    case "$line" in
      \#*) continue ;;
    esac
    NODE_WHITELIST_IPS+=("$line")
  done < "$NODE_WHITELIST_FILE"
}

save_node_whitelist() {
  : > "$NODE_WHITELIST_FILE"
  local ip
  for ip in "${NODE_WHITELIST_IPS[@]}"; do
    printf '%s\n' "$ip" >> "$NODE_WHITELIST_FILE"
  done
}

sync_firewall_whitelist() {
  firewall_init_backend || return 1
  load_node_whitelist

  local ip
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

  warn "当前系统没有可用的防火墙后端。"
  return 1
}

# 开机防丢失：配置系统自启动服务同步白名单
setup_firewall_persistence() {
  info "正在配置防火墙开机持久化..."
  
  # 创建一个极轻量的同步脚本供 systemd 调用
  cat > "$SYNC_SCRIPT" << 'EOF'
#!/bin/bash
NODE_WHITELIST_FILE="/etc/ai_unlock/node_whitelist.conf"
FIREWALL_CHAIN="AI_UNLOCK_DNS"

if command -v nft >/dev/null 2>&1 && nft list table inet ai_unlock >/dev/null 2>&1; then
  nft flush set inet ai_unlock node_whitelist 2>/dev/null || true
  [ -f "$NODE_WHITELIST_FILE" ] || exit 0
  while IFS= read -r ip; do
    [[ -z "$ip" || "$ip" == \#* ]] && continue
    nft add element inet ai_unlock node_whitelist "{ $ip }" 2>/dev/null || true
  done < "$NODE_WHITELIST_FILE"
elif command -v iptables >/dev/null 2>&1 && iptables -nL "$FIREWALL_CHAIN" >/dev/null 2>&1; then
  iptables -F "$FIREWALL_CHAIN" 2>/dev/null || true
  [ -f "$NODE_WHITELIST_FILE" ] || exit 0
  while IFS= read -r ip; do
    [[ -z "$ip" || "$ip" == \#* ]] && continue
    iptables -A "$FIREWALL_CHAIN" -p udp --dport 53 -s "$ip" -j ACCEPT 2>/dev/null || true
    iptables -A "$FIREWALL_CHAIN" -p tcp --dport 53 -s "$ip" -j ACCEPT 2>/dev/null || true
  done < "$NODE_WHITELIST_FILE"
  iptables -A "$FIREWALL_CHAIN" -p udp --dport 53 -j DROP 2>/dev/null || true
  iptables -A "$FIREWALL_CHAIN" -p tcp --dport 53 -j DROP 2>/dev/null || true
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
    ok "防火墙重启防丢服务已配置完毕。"
  fi
}

remove_firewall_rules() {
  FIREWALL_BACKEND="$(firewall_detect_backend)"

  if [ "$FIREWALL_BACKEND" = "nftables" ]; then
    nft delete table inet ai_unlock 2>/dev/null || true
    ok "已清理 nftables 规则。"
    return 0
  fi

  if [ "$FIREWALL_BACKEND" = "iptables" ]; then
    iptables -D INPUT -p udp --dport 53 -j "$FIREWALL_CHAIN" 2>/dev/null || true
    iptables -D INPUT -p tcp --dport 53 -j "$FIREWALL_CHAIN" 2>/dev/null || true
    iptables -F "$FIREWALL_CHAIN" 2>/dev/null || true
    iptables -X "$FIREWALL_CHAIN" 2>/dev/null || true
    ok "已清理 iptables 规则。"
    return 0
  fi

  return 0
}

list_firewall_whitelist() {
  firewall_init_backend || return 1
  load_node_whitelist

  printf "防火墙后端: %s\n" "$FIREWALL_BACKEND"
  printf "白名单文件: %s\n" "$NODE_WHITELIST_FILE"
  if [ "${#NODE_WHITELIST_IPS[@]}" -eq 0 ]; then
    printf "  暂无节点 IP\n"
  else
    local ip
    for ip in "${NODE_WHITELIST_IPS[@]}"; do
      printf "  %s\n" "$ip"
    done
  fi
}

firewall_add_ip() {
  read -r -p "请输入要放行的节点 IP: " ip
  if ! validate_ipv4 "$ip"; then
    warn "IP 格式不正确。"
    return
  fi

  load_node_whitelist
  local item
  for item in "${NODE_WHITELIST_IPS[@]}"; do
    if [ "$item" = "$ip" ]; then
      warn "该 IP 已存在。"
      return
    fi
  done

  NODE_WHITELIST_IPS+=("$ip")
  save_node_whitelist
  sync_firewall_whitelist
}

firewall_add_batch() {
  read -r -p "请输入多个 IP（空格或逗号分隔）: " list
  list="$(printf '%s' "$list" | tr ',' ' ')"

  load_node_whitelist
  local ip item exists
  for ip in $list; do
    validate_ipv4 "$ip" || continue
    exists=0
    for item in "${NODE_WHITELIST_IPS[@]}"; do
      if [ "$item" = "$ip" ]; then
        exists=1
        break
      fi
    done
    if [ "$exists" -eq 0 ]; then
      NODE_WHITELIST_IPS+=("$ip")
      ok "已加入 $ip"
    fi
  done
  save_node_whitelist
  sync_firewall_whitelist
}

firewall_delete_rule() {
  load_node_whitelist
  if [ "${#NODE_WHITELIST_IPS[@]}" -eq 0 ]; then
    warn "当前没有白名单。"
    return
  fi

  list_firewall_whitelist
  read -r -p "请输入要删除的节点 IP: " ip
  if ! validate_ipv4 "$ip"; then
    warn "IP 格式不正确。"
    return
  fi

  local next=() item removed=0
  for item in "${NODE_WHITELIST_IPS[@]}"; do
    if [ "$item" = "$ip" ]; then
      removed=1
      continue
    fi
    next+=("$item")
  done

  if [ "$removed" -eq 0 ]; then
    warn "未找到该 IP。"
    return
  fi

  NODE_WHITELIST_IPS=("${next[@]}")
  save_node_whitelist
  sync_firewall_whitelist
}

firewall_clear() {
  read -r -p "确认清空所有节点白名单？(y/n): " confirm
  if [ "$confirm" != "y" ]; then
    return
  fi

  NODE_WHITELIST_IPS=()
  save_node_whitelist
  sync_firewall_whitelist
}

is_unlock_installed() {
  if [ -f "$DNSMASQ_CONF" ] || [ -f "$SNI_CONF" ]; then
    return 0
  fi

  if command_exists systemctl; then
    systemctl is-active dnsmasq >/dev/null 2>&1 && return 0
    systemctl is-active sniproxy >/dev/null 2>&1 && return 0
  fi

  return 1
}

port_53_is_busy() {
  command_exists ss && ss -luntp 2>/dev/null | grep -E ':53[[:space:]]' >/dev/null 2>&1
}

validate_ipv4() {
  local ip="$1"
  local a b c d extra
  IFS=. read -r a b c d extra <<EOF
$ip
EOF
  [ -n "$a" ] && [ -n "$b" ] && [ -n "$c" ] && [ -n "$d" ] && [ -z "$extra" ] || return 1
  for octet in "$a" "$b" "$c" "$d"; do
    case "$octet" in
      ''|*[!0-9]*) return 1 ;;
    esac
    [ "$octet" -ge 0 ] 2>/dev/null && [ "$octet" -le 255 ] 2>/dev/null || return 1
  done
  return 0
}

backup_unlock_resolv_conf() {
  ensure_base_dir
  if [ ! -f "$UNLOCK_RESOLV_BACKUP" ]; then
    cp -a /etc/resolv.conf "$UNLOCK_RESOLV_BACKUP" 2>/dev/null || true
  fi
}

restore_unlock_resolv_conf() {
  if [ -f "$UNLOCK_RESOLV_BACKUP" ]; then
    chattr -i /etc/resolv.conf 2>/dev/null || true
    cp -a "$UNLOCK_RESOLV_BACKUP" /etc/resolv.conf 2>/dev/null || true
    ok "已恢复本机 DNS。"
  else
    warn "未找到 DNS 备份。"
  fi
}

write_public_resolv_conf() {
  chattr -i /etc/resolv.conf 2>/dev/null || true
  rm -f /etc/resolv.conf
  {
    local dns
    for dns in "${PUBLIC_DNS_SERVERS[@]}"; do
      printf 'nameserver %s\n' "$dns"
    done
  } > /etc/resolv.conf
}

release_port_53() {
  local released=0

  if command_exists systemctl && systemctl is-active systemd-resolved >/dev/null 2>&1; then
    info "检测到 systemd-resolved 占用 53 端口，正在关闭..."
    systemctl stop systemd-resolved 2>/dev/null || true
    systemctl disable systemd-resolved 2>/dev/null || true
    released=1
  fi

  if port_53_is_busy; then
    info "53 端口仍有监听，尝试强制释放..."
    if command_exists fuser; then
      fuser -k 53/tcp 53/udp 2>/dev/null || true
      released=1
    fi
  fi

  sleep 1
  return 0
}

check_ai_endpoint() {
  local url="$1"
  local code
  code="$(curl -k -sS -L --connect-timeout 5 --max-time 10 -o /dev/null -w '%{http_code}' "$url" 2>/dev/null || true)"

  if [ -n "$code" ] && [ "$code" != "000" ]; then
    printf "  [OK]   %s -> HTTP %s\n" "$url" "$code"
    return 0
  fi

  printf "  [FAIL] %s\n" "$url"
  return 1
}

show_port_53_listeners() {
  printf "53 端口监听：\n"
  if ! command_exists ss; then
    printf "  ss 不可用，无法检查。\n"
    return
  fi

  if port_53_is_busy; then
    ss -luntp 2>/dev/null | awk 'NR==1 || /:53[[:space:]]/'
  else
    printf "  未发现占用。\n"
  fi
}

show_systemd_resolved_status() {
  printf "systemd-resolved：\n"
  if command_exists systemctl; then
    printf "  active: %s\n" "$(systemctl is-active systemd-resolved 2>/dev/null || echo unknown)"
    printf "  enabled: %s\n" "$(systemctl is-enabled systemd-resolved 2>/dev/null || echo unknown)"
  else
    printf "  systemctl 不可用。\n"
  fi

  if command_exists ss && ss -luntp 2>/dev/null | grep -q 'systemd-resolved'; then
    printf "  53监听: 是\n"
  else
    printf "  53监听: 否\n"
  fi
}

show_unlock_service_status() {
  printf "服务状态：\n"
  printf "  dnsmasq: %s\n" "$(service_status dnsmasq)"
  printf "  sniproxy: %s\n" "$(service_status sniproxy)"
}

show_unlock_config_status() {
  printf "配置状态：\n"
  printf "  dnsmasq.conf: %s\n" "$([ -s "$DNSMASQ_CONF" ] && echo ready || echo missing)"
  printf "  sniproxy.conf: %s\n" "$([ -s "$SNI_CONF" ] && echo ready || echo missing)"
  printf "  自定义域名: %s\n" "$([ -s "$CUSTOM_DOMAIN_FILE" ] && wc -l < "$CUSTOM_DOMAIN_FILE" || echo 0)"
}

show_firewall_support_status() {
  printf "防火墙支持：\n"
  FIREWALL_BACKEND="$(firewall_detect_backend)"
  printf "  后端: %s\n" "$FIREWALL_BACKEND"
  printf "  白名单文件: %s\n" "$NODE_WHITELIST_FILE"
}

show_ai_connectivity() {
  printf "AI 连通性：\n"
  local url
  local ok_count=0
  for url in "${AI_CHECK_URLS[@]}"; do
    if check_ai_endpoint "$url"; then
      ok_count=$((ok_count + 1))
    fi
  done
  printf "  通过项: %s/%s\n" "$ok_count" "${#AI_CHECK_URLS[@]}"
}

show_unlock_summary() {
  printf "主机 IP: %s\n" "$(detect_public_ip)"
  show_port_53_listeners
  show_systemd_resolved_status
  show_unlock_service_status
  show_unlock_config_status
  show_firewall_support_status
  show_ai_connectivity
}

unlock_detection_menu() {
  while true; do
    clear
    printf "%b\n" "$(color 36 "======================================")"
    printf "%b\n" "$(color 36 "             👁️ 解锁机检测")"
    printf "%b\n" "$(color 36 "======================================")"
    printf "  %b 53 端口监听检查\n" "$(color 32 "1.")"
    printf "  %b systemd-resolved 检查\n" "$(color 32 "2.")"
    printf "  %b AI 连通性检查\n" "$(color 32 "3.")"
    printf "  %b 服务与配置检查\n" "$(color 32 "4.")"
    printf "  %b 综合检测\n" "$(color 32 "5.")"
    printf "  %b 返回\n" "$(color 32 "0.")"
    printf "%b\n" "$(color 36 "======================================")"
    read -r -p "请选择 [0-5]: " choice

    case "$choice" in
      1) show_port_53_listeners; pause ;;
      2) show_systemd_resolved_status; pause ;;
      3) show_ai_connectivity; pause ;;
      4) show_unlock_service_status; show_unlock_config_status; pause ;;
      5) show_unlock_summary; pause ;;
      0) return ;;
      *) warn "无效选项"; sleep 1 ;;
    esac
  done
}

prepare_unlock_environment() {
  backup_unlock_resolv_conf
  release_port_53
  write_public_resolv_conf
}

verify_unlock_environment() {
  if port_53_is_busy; then
    err "53 端口仍被占用，无法继续安装。"
    show_port_53_listeners
    return 1
  fi

  if command_exists systemctl && systemctl is-active systemd-resolved >/dev/null 2>&1; then
    warn "systemd-resolved 仍在运行。"
  fi

  return 0
}

sanitize_domain() {
  printf '%s' "$1" \
    | sed -e 's#^[a-zA-Z][a-zA-Z0-9+.-]*://##' \
          -e 's#^\\*\\.##' \
          -e 's#/.*##' \
          -e 's/:.*//'
}

write_custom_domains() {
  : > "$CUSTOM_DOMAIN_FILE"
  local domain
  for domain in "${CUSTOM_DOMAINS[@]}"; do
    printf '%s\n' "$domain" >> "$CUSTOM_DOMAIN_FILE"
  done
}

collect_domains() {
  declare -A seen=()
  local domain

  for domain in "${BASE_DOMAINS[@]}"; do
    domain="$(sanitize_domain "$domain")"
    [ -z "$domain" ] && continue
    if [ -z "${seen[$domain]+x}" ]; then
      seen["$domain"]=1
      printf '%s\n' "$domain"
    fi
  done

  load_custom_domains
  for domain in "${CUSTOM_DOMAINS[@]}"; do
    domain="$(sanitize_domain "$domain")"
    [ -z "$domain" ] && continue
    if [ -z "${seen[$domain]+x}" ]; then
      seen["$domain"]=1
      printf '%s\n' "$domain"
    fi
  done
}

escape_regex_domain() {
  printf '%s' "$1" | sed 's/\./\\./g'
}

ensure_dnsmasq_dir() {
  mkdir -p /etc/dnsmasq.d
}

update_rules() {
  ensure_base_dir
  ensure_dnsmasq_dir

  SERVER_IP="$(detect_public_ip)"
  if [ -z "$SERVER_IP" ]; then
    err "未能获取解锁机公网 IP。"
    return 1
  fi

  info "正在生成配置文件..."

  {
    printf '# generated by ai_unlock installer\n'
    while IFS= read -r domain; do
      [ -z "$domain" ] && continue
      printf 'address=/%s/%s\n' "$domain" "$SERVER_IP"
    done < <(collect_domains)
  } > "$DNSMASQ_CONF"

  {
    cat <<'EOF'
user daemon
pidfile /var/run/sniproxy.pid
error_log {
    syslog daemon
    priority notice
}
listen 443 {
    proto tls
    table https_hosts
    fallback reject
}
table https_hosts {
EOF

    while IFS= read -r domain; do
      [ -z "$domain" ] && continue
      escaped="$(escape_regex_domain "$domain")"
      printf '    ^%s$ *\n' "$escaped"
      printf '    .*\\.%s$ *\n' "$escaped"
    done < <(collect_domains)

    printf '}\n'
  } > "$SNI_CONF"

  service_restart dnsmasq
  service_restart sniproxy
  ok "域名规则已更新。"
}

show_domain_pool() {
  load_custom_domains
  printf "\n%s\n" "$(color 36 "默认域名池")"
  printf '  %s\n' "${BASE_DOMAINS[@]}"

  printf "\n%s\n" "$(color 36 "自定义域名池")"
  if [ "${#CUSTOM_DOMAINS[@]}" -eq 0 ]; then
    printf '  %s\n' "暂无"
  else
    printf '  %s\n' "${CUSTOM_DOMAINS[@]}"
  fi
}

add_custom_domain() {
  read -r -p "请输入要添加的域名: " domain
  domain="$(sanitize_domain "$domain")"
  if [ -z "$domain" ]; then
    warn "域名不能为空。"
    return
  fi

  load_custom_domains
  local item
  for item in "${CUSTOM_DOMAINS[@]}"; do
    if [ "$item" = "$domain" ]; then
      warn "该域名已存在。"
      return
    fi
  done

  CUSTOM_DOMAINS+=("$domain")
  write_custom_domains
  ok "已添加 $domain"
}

remove_custom_domain() {
  load_custom_domains
  if [ "${#CUSTOM_DOMAINS[@]}" -eq 0 ]; then
    warn "当前没有自定义域名。"
    return
  fi

  read -r -p "请输入要删除的自定义域名: " domain
  domain="$(sanitize_domain "$domain")"
  if [ -z "$domain" ]; then
    warn "域名不能为空。"
    return
  fi

  local next=() item removed=0
  for item in "${CUSTOM_DOMAINS[@]}"; do
    if [ "$item" = "$domain" ]; then
      removed=1
      continue
    fi
    next+=("$item")
  done

  if [ "$removed" -eq 0 ]; then
    warn "未找到该域名。"
    return
  fi

  CUSTOM_DOMAINS=("${next[@]}")
  write_custom_domains
  ok "已删除 $domain"
}

clear_custom_domains() {
  read -r -p "确认清空所有自定义域名？(y/n): " confirm
  if [ "$confirm" = "y" ]; then
    CUSTOM_DOMAINS=()
    write_custom_domains
    ok "自定义域名池已清空。"
  fi
}

reset_custom_domains() {
  read -r -p "确认恢复默认域名池并清空自定义域名？(y/n): " confirm
  if [ "$confirm" = "y" ]; then
    : > "$CUSTOM_DOMAIN_FILE"
    ok "已恢复默认域名池。"
  fi
}

domain_menu() {
  while true; do
    clear
    printf "%b\n" "$(color 36 "======================================")"
    printf "%b\n" "$(color 36 "         域名池管理")"
    printf "%b\n" "$(color 36 "======================================")"
    printf "  %b 查看当前域名池\n" "$(color 32 "1.")"
    printf "  %b 添加自定义域名\n" "$(color 32 "2.")"
    printf "  %b 删除自定义域名\n" "$(color 32 "3.")"
    printf "  %b 清空自定义域名\n" "$(color 32 "4.")"
    printf "  %b 恢复默认域名池\n" "$(color 32 "5.")"
    printf "  %b 返回\n" "$(color 32 "0.")"
    printf "%b\n" "$(color 36 "======================================")"
    read -r -p "请选择 [0-5]: " choice

    case "$choice" in
      1) show_domain_pool; pause ;;
      2) add_custom_domain; pause ;;
      3) remove_custom_domain; pause ;;
      4) clear_custom_domains; pause ;;
      5) reset_custom_domains; pause ;;
      0) return ;;
      *) warn "无效选项"; sleep 1 ;;
    esac
  done
}

firewall_menu() {
  while true; do
    clear
    printf "%b\n" "$(color 36 "======================================")"
    printf "%b\n" "$(color 36 "         节点白名单管理")"
    printf "%b\n" "$(color 36 "======================================")"
    printf "  %b 查看当前白名单\n" "$(color 32 "1.")"
    printf "  %b 添加单个节点 IP\n" "$(color 32 "2.")"
    printf "  %b 批量添加节点 IP\n" "$(color 32 "3.")"
    printf "  %b 移除单个节点 IP\n" "$(color 32 "4.")"
    printf "  %b 清空所有节点白名单\n" "$(color 32 "5.")"
    printf "  %b 返回\n" "$(color 32 "0.")"
    printf "%b\n" "$(color 36 "======================================")"
    read -r -p "请选择 [0-5]: " choice

    case "$choice" in
      1) list_firewall_whitelist; pause ;;
      2) firewall_add_ip; pause ;;
      3) firewall_add_batch; pause ;;
      4) firewall_delete_rule; pause ;;
      5) firewall_clear; pause ;;
      0) return ;;
      *) warn "无效选项"; sleep 1 ;;
    esac
  done
}

install_unlock_core() {
  info "正在安装基础组件..."
  install_packages dnsmasq sniproxy curl e2fsprogs iproute2 psmisc || return 1
  install_firewall_tools || warn "未检测到 nftables/iptables，节点白名单功能将不可用。"

  ensure_base_dir

  info "正在进行安装前检查..."
  show_port_53_listeners
  show_systemd_resolved_status
  show_ai_connectivity

  if ! confirm_reinstall_requested; then
    return 1
  fi

  prepare_unlock_environment || return 1
  verify_unlock_environment || return 1
  firewall_init_backend || warn "未检测到可用防火墙后端，白名单功能将不可用。"

  service_enable dnsmasq
  service_enable sniproxy

  update_rules

  service_start dnsmasq
  service_start sniproxy

  if [ "$(service_status dnsmasq)" = "active" ] && [ "$(service_status sniproxy)" = "active" ]; then
    ok "解锁机核心已完成。"
  else
    warn "部分服务未处于 active 状态，请查看检测菜单。"
  fi
  
  # 在安装最后设置防火墙开机持久化
  setup_firewall_persistence
  
  show_unlock_summary
  printf "公网 IP: %s\n" "$(detect_public_ip)"
}

uninstall_unlock_core() {
  read -r -p "确认卸载并删除配置？(y/n): " confirm
  if [ "$confirm" != "y" ]; then
    return
  fi

  # 清理自启动服务
  if command_exists systemctl; then
    systemctl disable ai-unlock-firewall.service 2>/dev/null || true
    systemctl stop ai-unlock-firewall.service 2>/dev/null || true
    rm -f "$SYSTEMD_SERVICE"
    systemctl daemon-reload 2>/dev/null || true
  fi
  rm -f "$SYNC_SCRIPT"

  rm -f "$DNSMASQ_CONF" "$SNI_CONF"
  remove_firewall_rules
  restore_unlock_resolv_conf
  service_restart dnsmasq 2>/dev/null
  service_restart sniproxy 2>/dev/null
  ok "已清理配置文件。"
}

confirm_reinstall_requested() {
  if ! is_unlock_installed; then
    return 0
  fi

  read -r -p "检测到已安装，是否重新安装？(y/N): " confirm
  case "$confirm" in
    y|Y) return 0 ;;
    *) warn "已取消安装。"; return 1 ;;
  esac
}

unlock_menu() {
  while true; do
    clear
    printf "%b\n" "$(color 36 "======================================")"
    printf "%b\n" "$(color 36 "           搭建【解锁机】")"
    printf "%b\n" "$(color 36 "======================================")"
    printf "  %b 安装核心环境\n" "$(color 32 "1.")"
    printf "  %b 检测 / 预检\n" "$(color 32 "2.")"
    printf "  %b 域名池管理\n" "$(color 32 "3.")"
    printf "  %b 节点白名单管理\n" "$(color 32 "4.")"
    printf "  %b 查看服务状态\n" "$(color 32 "5.")"
    printf "  %b 卸载 / 回滚\n" "$(color 32 "6.")"
    printf "  %b 返回主菜单\n" "$(color 32 "0.")"
    printf "%b\n" "$(color 36 "======================================")"
    read -r -p "请选择 [0-6]: " choice

    case "$choice" in
      1) install_unlock_core; pause ;;
      2) unlock_detection_menu ;;
      3) domain_menu ;;
      4) firewall_menu ;;
      5)
        show_unlock_service_status
        show_unlock_config_status
        pause
        ;;
      6) uninstall_unlock_core; pause ;;
      0) return ;;
      *) warn "无效选项"; sleep 1 ;;
    esac
  done
}

set_node_dns() {
  read -r -p "请输入解锁机公网 IP: " unlock_ip
  if [ -z "$unlock_ip" ]; then
    warn "IP 不能为空。"
    return
  fi

  backup_resolv_conf
  chattr -i /etc/resolv.conf 2>/dev/null || true
  {
    printf 'nameserver %s\n' "$unlock_ip"
    printf 'nameserver 1.1.1.1\n'
    printf 'nameserver 8.8.8.8\n'
  } > /etc/resolv.conf
  chattr +i /etc/resolv.conf 2>/dev/null || true

  ok "本机 DNS 已指向解锁机。"
}

test_node_dns() {
  local domain="${1:-chatgpt.com}"
  local resolved=""

  if command_exists getent; then
    resolved="$(getent ahostsv4 "$domain" | awk 'NR==1 {print $1}')"
  fi

  if [ -n "$resolved" ]; then
    printf "解析结果: %s -> %s\n" "$domain" "$resolved"
  else
    warn "未能获取解析结果，请确认节点机 DNS 已切到解锁机。"
  fi
}

show_resolv_conf() {
  printf "\n%s\n" "$(color 36 "/etc/resolv.conf")"
  cat /etc/resolv.conf 2>/dev/null || true
}

node_menu() {
  while true; do
    clear
    printf "%b\n" "$(color 36 "======================================")"
    printf "%b\n" "$(color 36 "           配置【节点机】")"
    printf "%b\n" "$(color 36 "======================================")"
    printf "  %b 指定解锁机 DNS\n" "$(color 32 "1.")"
    printf "  %b 恢复本机 DNS\n" "$(color 32 "2.")"
    printf "  %b 测试分流解析\n" "$(color 32 "3.")"
    printf "  %b 查看当前 DNS 配置\n" "$(color 32 "4.")"
    printf "  %b 返回主菜单\n" "$(color 32 "0.")"
    printf "%b\n" "$(color 36 "======================================")"
    read -r -p "请选择 [0-4]: " choice

    case "$choice" in
      1) set_node_dns; pause ;;
      2) restore_resolv_conf; pause ;;
      3) test_node_dns; pause ;;
      4) show_resolv_conf; pause ;;
      0) return ;;
      *) warn "无效选项"; sleep 1 ;;
    esac
  done
}

main_menu() {
  while true; do
    clear
    printf "%b\n" "$(color 36 "======================================")"
    printf "%b\n" "$(color 36 "         AI DNS 分流管理")"
    printf "%b\n" "$(color 36 "======================================")"
    printf "  %b 搭建【解锁机】\n" "$(color 32 "1.")"
    printf "  %b 配置【节点机】\n" "$(color 32 "2.")"
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
  ensure_root
  ensure_base_dir
  main_menu
}

main "$@"
