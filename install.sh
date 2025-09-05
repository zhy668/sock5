#!/bin/bash

# 确保脚本在发生错误时退出
set -e

# --- 全局函数定义 ---

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# 检查是否以root用户运行
check_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "Error: This script needs to be run with root privileges."
    echo "Please try using 'sudo ./your_script_name.sh' to run."
    exit 1
  fi
}

# 缓存公网IP以提高状态检查速度
get_cached_public_ip() {
    local cache_file="/tmp/proxy_public_ip"
    local cache_timeout=300  # 5 minutes cache
    local cached_ip=""
    local cache_age=0

    # Check if cache file exists and not expired
    if [ -f "$cache_file" ]; then
        cache_age=$(($(date +%s) - $(stat -c %Y "$cache_file" 2>/dev/null || echo 0)))
        if [ $cache_age -lt $cache_timeout ]; then
            cached_ip=$(cat "$cache_file" 2>/dev/null)
        fi
    fi

    # If cache is valid, return directly
    if [ ! -z "$cached_ip" ] && [ "$cached_ip" != "FAILED" ]; then
        echo "$cached_ip"
        return
    fi

    # Get new IP and cache it
    local new_ip=$(timeout 3 curl -s http://ipv4.icanhazip.com/ 2>/dev/null || timeout 3 curl -s http://checkip.amazonaws.com/ 2>/dev/null || echo "FAILED")
    echo "$new_ip" > "$cache_file" 2>/dev/null
    echo "$new_ip"
}

# 检查并显示当前服务状态
check_status() {
    clear
    echo -e "${BOLD}${CYAN}================================================================${NC}"
    echo -e "${BOLD}${WHITE}                    >> Proxy Service Center <<                    ${NC}"
    echo -e "${BOLD}${WHITE}                HTTP & SOCKS5 Proxy Management Tool                ${NC}"
    echo -e "${BOLD}${CYAN}================================================================${NC}"
    echo ""
    echo -e "${BOLD}${YELLOW}[Status Check] Current Service Status:${NC}"

    # Get public IP (using cache mechanism to avoid repeated network requests)
    local public_ip=$(get_cached_public_ip)

    # Check SOCKS5 (Dante) status
    echo -e "${CYAN}+---------------------------------------------------------------+${NC}"
    if ! systemctl list-unit-files 2>/dev/null | grep -q 'danted.service'; then
        echo -e "${CYAN}|${NC} ${BLUE}[SOCKS5]${NC} ${RED}[X] Not Installed${NC}                                    ${CYAN}|${NC}"
    elif systemctl is-active --quiet danted 2>/dev/null; then
        local socks_port=$(grep -oP 'port = \K\d+' /etc/danted.conf 2>/dev/null || echo "Unknown")
        echo -e "${CYAN}|${NC} ${BLUE}[SOCKS5]${NC} ${GREEN}[√] Running${NC}                                   ${CYAN}|${NC}"
        echo -e "${CYAN}|${NC}    ${YELLOW}Connect: ${WHITE}socks5://$public_ip:$socks_port${NC}              ${CYAN}|${NC}"
        echo -e "${CYAN}|${NC}    ${YELLOW}Auth: ${WHITE}System User Password${NC}                                ${CYAN}|${NC}"
    else
        echo -e "${CYAN}|${NC} ${BLUE}[SOCKS5]${NC} ${RED}[X] Installed but Not Running${NC}                           ${CYAN}|${NC}"
    fi
    echo -e "${CYAN}+---------------------------------------------------------------+${NC}"

    # Check HTTP (Squid) status
    if systemctl is-active --quiet squid 2>/dev/null; then
        local http_port=$(grep -oP 'http_port\s+\K\d+' /etc/squid/squid.conf 2>/dev/null || echo "Unknown")
        local http_user="Unknown"
        local http_pass="Unknown"

        # Try to get username and password from auth file
        if [ -f "/etc/squid/passwd" ]; then
            http_user=$(cut -d: -f1 /etc/squid/passwd 2>/dev/null | head -1)
            # Get password from installation temp file
            if [ -f "/tmp/squid_password" ]; then
                http_pass=$(cat /tmp/squid_password 2>/dev/null)
            else
                http_pass="[Check Install Log]"
            fi
        fi

        echo -e "${CYAN}|${NC} ${PURPLE}[HTTP]${NC}   ${GREEN}[√] Running${NC}                                  ${CYAN}|${NC}"
        echo -e "${CYAN}|${NC}    ${YELLOW}Connect: ${WHITE}http://$public_ip:$http_port${NC}                 ${CYAN}|${NC}"
        echo -e "${CYAN}|${NC}    ${YELLOW}User: ${WHITE}$http_user${NC}                                    ${CYAN}|${NC}"
        echo -e "${CYAN}|${NC}    ${YELLOW}Pass: ${WHITE}$http_pass${NC}                                      ${CYAN}|${NC}"
    else
        echo -e "${CYAN}|${NC} ${PURPLE}[HTTP]${NC}   ${RED}[X] Not Installed or Not Running${NC}                         ${CYAN}|${NC}"
    fi
    echo -e "${CYAN}+---------------------------------------------------------------+${NC}"
    echo ""
}

# 快速详细状态检查
quick_detailed_status() {
    clear
    echo -e "${BOLD}${CYAN}================================================================${NC}"
    echo -e "${BOLD}${WHITE}                    >> Detailed Status Report <<                    ${NC}"
    echo -e "${BOLD}${CYAN}================================================================${NC}"
    echo ""

    # Get public IP
    local public_ip=$(get_cached_public_ip)
    echo -e "${BOLD}${YELLOW}[Server Information]${NC}"
    echo -e "   ${YELLOW}Public IP:${NC} ${WHITE}$public_ip${NC}"
    echo -e "   ${YELLOW}System:${NC}   ${WHITE}$(uname -s) $(uname -r)${NC}"
    echo ""

    # 检查SOCKS5状态
    echo "┌─ � SOCKS5 (Dante) 详细状态 ─────────────────────────────────┐"
    if ! systemctl list-unit-files 2>/dev/null | grep -q 'danted.service'; then
        echo "│   状态: ❌ 未安装                                           │"
        echo "│   建议: 选择菜单选项 1 进行安装                             │"
    elif systemctl is-active --quiet danted 2>/dev/null; then
        local socks_port=$(grep -oP 'port = \K\d+' /etc/danted.conf 2>/dev/null || echo "未知")
        echo "│   状态: ✅ 运行中                                           │"
        echo "│   端口: $socks_port                                         │"
        echo "│   连接: socks5://$public_ip:$socks_port                     │"
        echo "│   认证: 系统用户密码                                       │"
        echo "│   配置: /etc/danted.conf                                   │"
        echo "│   日志: journalctl -u danted --no-pager -l                │"
    else
        echo "│   状态: ❌ 已安装但未运行                                   │"
        echo "│   建议: systemctl start danted                            │"
        echo "│   日志: journalctl -u danted --no-pager -l                │"
    fi
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    # 检查HTTP状态
    echo "┌─ � HTTP (Squid) 详细状态 ──────────────────────────────────┐"
    if ! systemctl list-unit-files 2>/dev/null | grep -q 'squid.service'; then
        echo "│   状态: ❌ 未安装                                           │"
        echo "│   建议: 选择菜单选项 3 进行安装                             │"
    elif systemctl is-active --quiet squid 2>/dev/null; then
        local http_port=$(grep -oP 'http_port\s+\K\d+' /etc/squid/squid.conf 2>/dev/null || echo "未知")
        local http_user="未知"
        local http_pass="未知"

        if [ -f "/etc/squid/passwd" ]; then
            http_user=$(cut -d: -f1 /etc/squid/passwd 2>/dev/null | head -1)
            if [ -f "/tmp/squid_password" ]; then
                http_pass=$(cat /tmp/squid_password 2>/dev/null)
            else
                http_pass="[查看安装日志]"
            fi
        fi

        echo "│   状态: ✅ 运行中                                           │"
        echo "│   端口: $http_port                                          │"
        echo "│   连接: http://$public_ip:$http_port                        │"
        echo "│   用户: $http_user                                          │"
        echo "│   密码: $http_pass                                          │"
        echo "│   配置: /etc/squid/squid.conf                              │"
        echo "│   认证: /etc/squid/passwd                                  │"
        echo "│   日志: journalctl -u squid --no-pager -l                 │"
    else
        echo "│   状态: ❌ 已安装但未运行                                   │"
        echo "│   建议: systemctl start squid                             │"
        echo "│   日志: journalctl -u squid --no-pager -l                 │"
    fi
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    # 系统资源信息
    echo "┌─ 📊 系统资源使用情况 ───────────────────────────────────────┐"
    if command -v free >/dev/null 2>&1; then
        echo "│   💾 内存使用: $(free -h | awk 'NR==2{printf "%.1f%%", $3*100/$2 }')                                      │"
    fi
    if command -v df >/dev/null 2>&1; then
        echo "│   💿 磁盘使用: $(df -h / | awk 'NR==2{print $5}')                                        │"
    fi
    if command -v uptime >/dev/null 2>&1; then
        echo "│   ⚡ 负载均衡: $(uptime | awk -F'load average:' '{ print $2 }' | sed 's/^[ \t]*//')                                      │"
    fi
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    ⚡ 详细状态检查完成！ ⚡                   ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
}

# 安装和配置 Dante
install_dante() {
    echo
    echo "===== Starting SOCKS5 (Dante) Proxy Installation ====="

    # 1. Get user input for port
    read -p "Enter SOCKS5 proxy port [default 8087]: " PORT
    PORT=${PORT:-8087}
    echo

    # 2. Install dante-server
    echo ">>> [1/6] Installing dante-server..."
    if [ -x "$(command -v apt-get)" ]; then
        apt-get update > /dev/null 2>&1
        apt-get install -y dante-server
    elif [ -x "$(command -v yum)" ]; then
        yum install -y epel-release
        yum install -y dante-server
    else
        echo "Error: Unsupported OS. Please run on Debian/Ubuntu/CentOS."
        exit 1
    fi
    echo ">>> dante-server installation completed."

    # 3. Configure PAM authentication
    echo ">>> [2/6] Configuring PAM authentication module..."
    PAM_CONF="/etc/pam.d/danted"
    tee $PAM_CONF > /dev/null <<EOF
#%PAM-1.0
auth       required   pam_unix.so
account    required   pam_unix.so
EOF
    echo ">>> PAM configuration completed."

    # 4. Write dante-server configuration file
    echo ">>> [3/6] Generating danted.conf configuration file..."
    IFACE=$(ip route get 8.8.8.8 | grep -oP 'dev \K\S+')
    CONF="/etc/danted.conf"
    [ -f $CONF ] && mv $CONF "$CONF.bak.$(date +%F-%T)"
    tee $CONF > /dev/null <<EOF
logoutput: syslog

# Key modification: Listen on all IPv4 interfaces, not just internal IP
internal: 0.0.0.0 port = $PORT
external: $IFACE

method: username
user.notprivileged: nobody

client pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    log: error connect disconnect
}
pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    log: error connect disconnect
}
EOF
    echo ">>> Configuration file written successfully."

    # 5. Configure firewall
    echo ">>> [4/6] Configuring firewall..."
    if command -v ufw >/dev/null 2>&1; then
        ufw allow $PORT/tcp
        echo ">>> Added UFW rule to allow port $PORT."
    elif command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port=$PORT/tcp
        firewall-cmd --reload
        echo ">>> Added firewalld rule to allow port $PORT."
    else
        echo ">>> UFW or firewalld not detected, please manually configure firewall to allow TCP port $PORT."
    fi

    # 6. Start service and enable auto-start
    echo ">>> [5/6] Starting danted service and enabling auto-start..."
    if systemctl restart danted 2>/dev/null && systemctl enable danted 2>/dev/null; then
        echo ">>> danted service started."
    else
        echo ">>> Warning: Service startup may have issues, continuing status check..."
    fi

    # 7. Monitor and confirm service status
    echo ">>> [6/6] Checking service running status..."
    # Wait for service to fully start, but reduce wait time
    sleep 0.5

    # Retry mechanism: try up to 3 times to check service status
    local retry_count=0
    local max_retries=3
    local service_running=false

    while [ $retry_count -lt $max_retries ]; do
        if systemctl is-active --quiet danted 2>/dev/null; then
            service_running=true
            break
        fi
        retry_count=$((retry_count + 1))
        if [ $retry_count -lt $max_retries ]; then
            echo ">>> Check $retry_count failed, retrying..."
            sleep 1
        fi
    done

    if [ "$service_running" = true ]; then
        # Get public IP with timeout mechanism
        PUBLIC_IP=$(timeout 5 curl -s http://ipv4.icanhazip.com/ 2>/dev/null || echo "FAILED")
        echo ""
        echo -e "${BOLD}${GREEN}================================================================${NC}"
        echo -e "${BOLD}${WHITE}                  >> SOCKS5 Proxy Installation Success! <<                 ${NC}"
        echo -e "${BOLD}${GREEN}================================================================${NC}"
        echo -e "${BOLD}${WHITE}  Connect Info: socks5://$PUBLIC_IP:$PORT                       ${NC}"
        echo -e "${BOLD}${WHITE}  Auth Method: System User Password (e.g. root)                         ${NC}"
        echo -e "${BOLD}${WHITE}  Service Status: Running                                         ${NC}"
        echo -e "${BOLD}${GREEN}================================================================${NC}"
    else
        echo ""
        echo -e "${BOLD}${RED}================================================================${NC}"
        echo -e "${BOLD}${WHITE}                  >> SOCKS5 Service Startup Failed! <<                  ${NC}"
        echo -e "${BOLD}${RED}================================================================${NC}"
        echo -e "${BOLD}${WHITE}  Please run the following command to view detailed error logs:                         ${NC}"
        echo -e "${BOLD}${WHITE}     journalctl -u danted --no-pager -l                      ${NC}"
        echo -e "${BOLD}${WHITE}  Or check configuration file:                                         ${NC}"
        echo -e "${BOLD}${WHITE}     cat /etc/danted.conf                                     ${NC}"
        echo -e "${BOLD}${RED}================================================================${NC}"
    fi
}

# 卸载 Dante
uninstall_dante() {
    echo
    read -p "您确定要卸载 SOCKS5 (Dante) 代理吗？这将删除所有配置。[y/N]: " choice
    case "$choice" in
      y|Y )
        echo "===== 开始卸载 SOCKS5 (Dante) 代理 ====="
        
        local port=$(grep -oP 'port = \K\d+' /etc/danted.conf || echo "")
        
        # 停止并禁用服务
        if systemctl list-unit-files | grep -q 'danted.service'; then
            echo ">>> [1/4] 正在停止并禁用 danted 服务..."
            systemctl stop danted || true
            systemctl disable danted || true
        fi

        # 新增：关闭防火墙端口
        if [ ! -z "$port" ]; then
            echo ">>> [2/4] 正在关闭防火墙端口 $port..."
            if command -v ufw >/dev/null 2>&1; then
                ufw delete allow $port/tcp
            elif command -v firewall-cmd >/dev/null 2>&1; then
                firewall-cmd --permanent --remove-port=$port/tcp
                firewall-cmd --reload
            fi
        fi

        # 卸载软件包
        echo ">>> [3/4] 正在卸载 dante-server 软件包..."
        if [ -x "$(command -v apt-get)" ]; then
            apt-get purge -y dante-server > /dev/null
        elif [ -x "$(command -v yum)" ]; then
            yum remove -y dante-server > /dev/null
        fi
        
        # 清理残留文件
        echo ">>> [4/4] 正在清理残留配置文件..."
        rm -f /etc/danted.conf*
        rm -f /etc/pam.d/danted
        
        echo
        echo "✅ SOCKS5 (Dante) 代理已成功卸载。"
        ;;
      * )
        echo "操作已取消。"
        ;;
    esac
}

# 安装并配置Squid HTTP代理
install_squid() {
    echo
    echo "===== 开始安装 HTTP (Squid) 代理 ====="
    read -p "请输入HTTP代理端口 [默认: 8888]: " PORT
    PORT=${PORT:-8888}

    read -p "请输入代理用户名 [默认: user]: " USER
    USER=${USER:-user}

    read -p "请输入代理密码 [默认: password123]: " PASS
    PASS=${PASS:-password123}

    echo
    echo ">>> [1/4] 正在安装 Squid 和认证工具..."
    if [ -x "$(command -v apt-get)" ]; then
        apt-get update > /dev/null 2>&1
        apt-get install -y squid apache2-utils
    elif [ -x "$(command -v yum)" ]; then
        yum install -y squid httpd-tools
    else
        echo "错误：不支持的系统。仅支持 Debian/Ubuntu 和 CentOS/RHEL。"
        exit 1
    fi

    echo ">>> [2/4] 正在配置 Squid..."
    # 备份原配置
    cp /etc/squid/squid.conf /etc/squid/squid.conf.backup

    # 创建简化配置
    cat > /etc/squid/squid.conf << EOF
# Squid HTTP代理配置文件
http_port $PORT

# 访问控制
acl localnet src 0.0.0.0/0
acl SSL_ports port 443
acl Safe_ports port 80 21 443 70 210 1025-65535 280 488 591 777
acl CONNECT method CONNECT

# 基本认证配置
auth_param basic program /usr/lib/squid3/basic_ncsa_auth /etc/squid/passwd
auth_param basic children 5
auth_param basic realm Squid proxy-caching web server
auth_param basic credentialsttl 2 hours
acl authenticated proxy_auth REQUIRED

# 访问规则
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow localhost manager
http_access deny manager
http_access allow authenticated
http_access allow localnet
http_access allow localhost
http_access deny all

# 缓存配置
cache_dir ufs /var/spool/squid 100 16 256
coredump_dir /var/spool/squid

# 日志配置
access_log /var/log/squid/access.log squid
cache_log /var/log/squid/cache.log

# 其他配置
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320

# 禁用Via头部以提高匿名性
via off
forwarded_for off
EOF

    echo ">>> [3/4] 正在创建用户认证..."
    htpasswd -cb /etc/squid/passwd "$USER" "$PASS"
    chown proxy:proxy /etc/squid/passwd
    chmod 640 /etc/squid/passwd

    # 保存密码到临时文件供状态检查使用
    echo "$PASS" > /tmp/squid_password
    chmod 600 /tmp/squid_password

    echo ">>> [4/4] 正在启动服务..."
    systemctl restart squid
    systemctl enable squid

    # 配置防火墙
    if command -v ufw >/dev/null 2>&1; then
        ufw allow $PORT/tcp
    elif command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port=$PORT/tcp
        firewall-cmd --reload
    fi

    # 检查服务状态
    echo ">>> 正在检查 Squid 服务状态..."
    sleep 1

    # 重试机制检查服务状态
    local retry_count=0
    local max_retries=3
    local service_running=false

    while [ $retry_count -lt $max_retries ]; do
        if systemctl is-active --quiet squid 2>/dev/null; then
            service_running=true
            break
        fi
        retry_count=$((retry_count + 1))
        if [ $retry_count -lt $max_retries ]; then
            echo ">>> 第 $retry_count 次检查失败，重试中..."
            sleep 1
        fi
    done

    if [ "$service_running" = true ]; then
        PUBLIC_IP=$(timeout 5 curl -s http://ipv4.icanhazip.com/ 2>/dev/null || echo "获取失败")
        echo ""
        echo "╔══════════════════════════════════════════════════════════════╗"
        echo "║                   🎉 HTTP 代理安装成功！ 🎉                  ║"
        echo "╠══════════════════════════════════════════════════════════════╣"
        echo "║  📡 连接信息: http://$PUBLIC_IP:$PORT                         ║"
        echo "║  👤 用户名: $USER                                            ║"
        echo "║  🔑 密码: $PASS                                              ║"
        echo "║  ✅ 服务状态: 运行中                                         ║"
        echo "╚══════════════════════════════════════════════════════════════╝"
    else
        echo ""
        echo "╔══════════════════════════════════════════════════════════════╗"
        echo "║                    HTTP 服务启动失败！                        ║"
        echo "╠══════════════════════════════════════════════════════════════╣"
        echo "║     请运行以下命令查看详细错误日志：                           ║"
        echo "║     journalctl -u squid --no-pager -l                        ║"
        echo "║     或检查配置文件：                                          ║"
        echo "║     cat /etc/squid/squid.conf                                ║"
        echo "╚══════════════════════════════════════════════════════════════╝"
    fi
}

# 卸载Squid HTTP代理
uninstall_squid() {
    echo
    read -p "您确定要卸载 HTTP (Squid) 代理吗？这将删除所有配置。[y/N]: " choice
    case "$choice" in
      y|Y )
        echo "===== 开始卸载 HTTP (Squid) 代理 ====="

        local port=$(grep -oP 'http_port\s+\K\d+' /etc/squid/squid.conf || echo "")

        # 停止并禁用服务
        if systemctl list-unit-files | grep -q 'squid.service'; then
            echo ">>> [1/4] 正在停止并禁用 squid 服务..."
            systemctl stop squid || true
            systemctl disable squid || true
        fi

        # 关闭防火墙端口
        if [ ! -z "$port" ]; then
            echo ">>> [2/4] 正在关闭防火墙端口 $port..."
            if command -v ufw >/dev/null 2>&1; then
                ufw delete allow $port/tcp || true
            elif command -v firewall-cmd >/dev/null 2>&1; then
                firewall-cmd --permanent --remove-port=$port/tcp || true
                firewall-cmd --reload || true
            fi
        fi

        # 卸载软件包
        echo ">>> [3/4] 正在卸载 squid..."
        if [ -x "$(command -v apt-get)" ]; then
            apt-get remove --purge -y squid
        elif [ -x "$(command -v yum)" ]; then
            yum remove -y squid
        fi

        # 清理配置文件
        echo ">>> [4/4] 正在清理配置文件..."
        rm -rf /etc/squid
        rm -rf /var/spool/squid
        rm -rf /var/log/squid

        echo
        echo "============================================"
        echo " HTTP (Squid) 代理已成功卸载！"
        echo "============================================"
        ;;
      * )
        echo "操作已取消。"
        ;;
    esac
}

# --- 主逻辑 ---

# 脚本开始时，先检查root权限
check_root

# 主菜单循环
while true; do
    check_status
    echo -e "${BOLD}${YELLOW}>> Please select an operation:${NC}"
    echo ""
    echo -e "${CYAN}+---------------------------------------------------------------+${NC}"
    echo -e "${CYAN}|${NC} ${BLUE}[SOCKS5 Proxy Management]${NC}                                         ${CYAN}|${NC}"
    echo -e "${CYAN}|${NC}  ${WHITE}1)${NC} ${GREEN}Install SOCKS5 (Dante) Proxy${NC}                               ${CYAN}|${NC}"
    echo -e "${CYAN}|${NC}  ${WHITE}2)${NC} ${RED}Uninstall SOCKS5 (Dante) Proxy${NC}                               ${CYAN}|${NC}"
    echo -e "${CYAN}+---------------------------------------------------------------+${NC}"
    echo ""
    echo -e "${CYAN}+---------------------------------------------------------------+${NC}"
    echo -e "${CYAN}|${NC} ${PURPLE}[HTTP Proxy Management]${NC}                                           ${CYAN}|${NC}"
    echo -e "${CYAN}|${NC}  ${WHITE}3)${NC} ${GREEN}Install HTTP (Squid) Proxy${NC}                                 ${CYAN}|${NC}"
    echo -e "${CYAN}|${NC}  ${WHITE}4)${NC} ${RED}Uninstall HTTP (Squid) Proxy${NC}                                 ${CYAN}|${NC}"
    echo -e "${CYAN}+---------------------------------------------------------------+${NC}"
    echo ""
    echo -e "${CYAN}+---------------------------------------------------------------+${NC}"
    echo -e "${CYAN}|${NC} ${YELLOW}[Other Options]${NC}                                                ${CYAN}|${NC}"
    echo -e "${CYAN}|${NC}  ${WHITE}5)${NC} ${BOLD}Quick Status Check (Detailed)${NC}                                 ${CYAN}|${NC}"
    echo -e "${CYAN}|${NC}  ${WHITE}0)${NC} ${BOLD}Exit Script${NC}                                               ${CYAN}|${NC}"
    echo -e "${CYAN}+---------------------------------------------------------------+${NC}"
    echo
    read -p "Enter option [0-5]: " main_choice

    case $main_choice in
        1)
            install_dante
            ;;
        2)
            uninstall_dante
            ;;
        3)
            install_squid
            ;;
        4)
            uninstall_squid
            ;;
        5)
            quick_detailed_status
            ;;
        0)
            echo "Exiting script."
            exit 0
            ;;
        *)
            echo "Invalid input, please enter a number between 0-5."
            ;;
    esac
    echo
    read -p "按 [Enter] 键返回主菜单..."
done
