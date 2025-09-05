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
    echo "错误：本脚本需要以 root 权限运行。"
    echo "请尝试使用 'sudo ./your_script_name.sh' 来运行。"
    exit 1
  fi
}

# ---------------- APT/YUM 加速与智能更新（仅脚本内生效） ----------------
# 说明：
# - 不修改系统源，仅在命令层面优化：强制IPv4、超时、重试、跳过推荐包、等待锁
# - 智能跳过 apt-get update：索引文件8小时内已更新则跳过（可用 APT_UPDATE_MAX_AGE 覆盖，单位秒）

# 等待 apt/dpkg 锁，最多等待 N 秒
apt_wait_for_locks() {
  local timeout=${1:-60}
  local waited=0
  while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 \
     || fuser /var/lib/apt/lists/lock >/dev/null 2>&1 \
     || fuser /var/lib/dpkg/lock >/dev/null 2>&1; do
    if [ "$waited" -ge "$timeout" ]; then
      echo ">>> 警告: 等待 apt/dpkg 锁超时(${timeout}s)，尝试继续..."
      return 0
    fi
    echo -ne ">>> 等待 apt/dpkg 锁释放... ${waited}s\r"
    sleep 2
    waited=$((waited+2))
  done
  echo -ne "\r"
}

# 获取 /var/lib/apt/lists 最新文件的修改时间（epoch秒）
apt_lists_latest_mtime() {
  local latest=0 ts f
  for f in /var/lib/apt/lists/*; do
    [ -f "$f" ] || continue
    ts=$(stat -c %Y "$f" 2>/dev/null || echo 0)
    [ "$ts" -gt "$latest" ] && latest="$ts"
  done
  echo "$latest"
}

# 智能执行 apt-get update（必要时才更新）
apt_smart_update_if_needed() {
  local max_age=${APT_UPDATE_MAX_AGE:-28800}  # 默认8小时
  local now=$(date +%s)
  local latest=$(apt_lists_latest_mtime)
  if [ "$latest" -gt 0 ] && [ $((now-latest)) -lt "$max_age" ]; then
    echo ">>> apt 索引较新(<=${max_age}s)，跳过 apt-get update"
    return 0
  fi
  apt_wait_for_locks 60
  DEBIAN_FRONTEND=noninteractive \
  apt-get -o Acquire::ForceIPv4=true \
          -o Acquire::Retries=3 \
          -o Acquire::http::Timeout=10 \
          -o Acquire::Languages=none \
          update -y > /dev/null 2>&1 || true
}

# 快速安装（APT）：强制IPv4、重试、超时、无推荐包
apt_fast_install() {
  apt_wait_for_locks 60
  DEBIAN_FRONTEND=noninteractive \
  apt-get -o Acquire::ForceIPv4=true \
          -o Acquire::Retries=3 \
          -o Acquire::http::Timeout=10 \
          -o Dpkg::Use-Pty=0 \
          -o Acquire::Languages=none \
          install -y --no-install-recommends "$@"
}

# YUM 加速：建立缓存与快速安装
yum_fast_makecache() {
  yum -y makecache fast >/dev/null 2>&1 || yum -y makecache >/dev/null 2>&1 || true
}

yum_fast_install() {
  yum -y --setopt=timeout=10 --setopt=retries=3 install "$@"
}

# 计时器：打印命令耗时（秒）
measure() {
  local label="$1"; shift
  local start=$(date +%s)
  "$@"
  local code=$?
  local end=$(date +%s)
  echo ">>> ${label} 用时 $((end-start)) 秒 (exit=$code)"
  return $code
}
# ---------------------------------------------------------------------


# 缓存公网IP以提高状态检查速度
get_cached_public_ip() {
    local cache_file="/tmp/proxy_public_ip"
    local cache_timeout=300  # 5分钟缓存
    local cached_ip=""
    local cache_age=0

    # 检查缓存文件是否存在且未过期
    if [ -f "$cache_file" ]; then
        cache_age=$(($(date +%s) - $(stat -c %Y "$cache_file" 2>/dev/null || echo 0)))
        if [ $cache_age -lt $cache_timeout ]; then
            cached_ip=$(cat "$cache_file" 2>/dev/null)
        fi
    fi

    # 如果缓存有效，直接返回
    if [ ! -z "$cached_ip" ] && [ "$cached_ip" != "获取失败" ]; then
        echo "$cached_ip"
        return
    fi

    # 获取新的IP并缓存
    local new_ip=$(timeout 3 curl -s http://ipv4.icanhazip.com/ 2>/dev/null || timeout 3 curl -s http://checkip.amazonaws.com/ 2>/dev/null || echo "获取失败")
    echo "$new_ip" > "$cache_file" 2>/dev/null
    echo "$new_ip"
}

# 检查并显示当前服务状态
check_status() {
    clear
    echo -e "${BOLD}${CYAN}================================================================${NC}"
    echo -e "${BOLD}${WHITE}                    >> 代理服务管理中心 <<                    ${NC}"
    echo -e "${BOLD}${WHITE}                HTTP & SOCKS5 代理一键管理工具                ${NC}"
    # 确保存在一个可用的系统用户用于认证（若无则引导创建）
    if ! id -u socksuser >/dev/null 2>&1; then
        read -p "是否创建系统用户 socksuser 用于Dante认证? [Y/n]: " CREATE_USER
        CREATE_USER=${CREATE_USER:-Y}
        if [[ "$CREATE_USER" =~ ^[Yy]$ ]]; then
            useradd -m -s /usr/sbin/nologin socksuser || true
            echo "请为 socksuser 设置密码（用于SOCKS5认证，与SSH无关）"
            passwd socksuser || true
        else
            echo "将使用你系统里已有用户进行认证（例如 root 或其他已有用户）。"
        fi
    fi

    echo -e "${BOLD}${CYAN}================================================================${NC}"
    echo ""
    echo -e "${BOLD}${YELLOW}[状态检查] 当前服务状态:${NC}"

    # 获取公网IP（使用缓存机制，避免重复网络请求）
    local public_ip=$(get_cached_public_ip)

    # 检查SOCKS5状态
    echo -e "${CYAN}+---------------------------------------------------------------+${NC}"
    if ! systemctl list-unit-files 2>/dev/null | grep -q 'danted.service'; then
        echo -e " ${BLUE}[SOCKS5]${NC} ${RED}[X] 未安装${NC}"
    elif systemctl is-active --quiet danted 2>/dev/null; then
        local socks_port=$(grep -oP 'port = \K\d+' /etc/danted.conf 2>/dev/null || echo "未知")
        echo -e " ${BLUE}[SOCKS5]${NC} ${GREEN}[OK] 运行中${NC}"
        echo -e "    ${YELLOW}连接: ${WHITE}socks5://$public_ip:$socks_port${NC}"
        echo -e "    ${YELLOW}认证: ${WHITE}系统用户密码${NC}"
    else
        echo -e " ${BLUE}[SOCKS5]${NC} ${RED}[X] 已安装但未运行${NC}"
    fi
    echo -e "${CYAN}+---------------------------------------------------------------+${NC}"

    # 检查HTTP状态
    if systemctl is-active --quiet squid 2>/dev/null; then
        local http_port=$(grep -oP 'http_port\s+\K\d+' /etc/squid/squid.conf 2>/dev/null || echo "未知")
        local http_user="未知"
        local http_pass="未知"

        # 尝试从认证文件中获取用户名和密码
        if [ -f "/etc/squid/passwd" ]; then
            http_user=$(cut -d: -f1 /etc/squid/passwd 2>/dev/null | head -1)
            # 优先从持久化文件获取密码
            if [ -f "/etc/squid/.password" ]; then
                http_pass=$(cat /etc/squid/.password 2>/dev/null)
            elif [ -f "/tmp/squid_password" ]; then
                http_pass=$(cat /tmp/squid_password 2>/dev/null)
            else
                http_pass="未知"
            fi
        fi

        echo -e "${NC} ${BLUE}[HTTP]${NC}   ${GREEN}[OK] 运行中${NC}                                  ${NC}"
        echo -e "${NC}    ${YELLOW}连接: ${WHITE}http://$public_ip:$http_port${NC}                 ${NC}"
        echo -e "${NC}    ${YELLOW}用户: ${WHITE}$http_user${NC}                                    ${NC}"
        echo -e "${NC}    ${YELLOW}密码: ${WHITE}$http_pass${NC}                                      ${NC}"
    else
        echo -e "${NC} ${BLUE}[HTTP]${NC}   ${RED}[X] 未安装或未运行${NC}                         ${NC}"
    fi
    echo -e "${CYAN}+---------------------------------------------------------------+${NC}"
    echo ""
}



# 安装和配置 Dante
install_dante() {
    echo
    echo "===== 开始安装 SOCKS5 代理 ====="

    # 1. 获取用户输入的端口
    read -p "请输入SOCKS5代理要使用的端口 [默认 8087]: " PORT
    PORT=${PORT:-8087}
    echo

    # 2. 安装 dante-server
    echo ">>> [1/6] 正在安装 dante-server..."
    if [ -x "$(command -v apt-get)" ]; then
        apt_smart_update_if_needed
        measure "dante-server 安装" apt_fast_install dante-server
    elif [ -x "$(command -v yum)" ]; then
        yum_fast_makecache
        measure "dante-server 安装(yum)" yum_fast_install dante-server
    else
        echo "错误：不支持的操作系统。请在 Debian/Ubuntu/CentOS 上运行。"
        exit 1
    fi
    echo ">>> dante-server 安装完成。"

    # 3. 配置PAM认证
    echo ">>> [2/6] 正在配置PAM认证模块..."
    # B方案：使用 libpam-pwdfile 与独立口令文件
    apt_smart_update_if_needed
    if ! measure "安装 libpam-pwdfile 与 htpasswd" apt_fast_install libpam-pwdfile apache2-utils; then
        echo ">>> 从官方源拉取失败，切换临时镜像到腾讯并重试..."
        switch_apt_to_tencent
        if ! measure "[重试] 安装 libpam-pwdfile 与 htpasswd" apt_fast_install libpam-pwdfile apache2-utils; then
            echo ">>> 镜像重试仍失败，建议稍后再试或检查网络。"
            restore_apt_sources_if_needed
            exit 1
        fi
        # 安装成功后可选择是否还原源，这里保持腾讯镜像以便后续安装更快；如需还原请解除下一行注释
        # restore_apt_sources_if_needed
    fi
    PAM_CONF="/etc/pam.d/danted"
    tee "$PAM_CONF" > /dev/null <<EOF
#%PAM-1.0
auth       required   pam_unix.so
account    required   pam_unix.so
EOF
    echo ">>> PAM配置完成。"

    # 4. 写入 dante-server 配置文件
    echo ">>> [3/6] 正在生成 danted.conf 配置文件..."
    IFACE=$(ip -4 route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' || ip route get 8.8.8.8 | awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}')
    CONF="/etc/danted.conf"
    [ -f $CONF ] && mv $CONF "$CONF.bak.$(date +%F-%T)"
    tee $CONF > /dev/null <<EOF
logoutput: syslog

# 关键修改：监听在所有IPv4接口上，而不是仅限内网IP
internal: 0.0.0.0 port = $PORT
external: $IFACE

# SOCKS5 方法：仅使用 username（PAM，系统用户）
method: username
user.notprivileged: nobody

client pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    log: error connect disconnect
}

# 认证与访问控制
socks pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    command: bind connect udpassociate
    log: error connect disconnect
}

pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    log: error connect disconnect
}
EOF
    echo ">>> 配置文件写入完成。"

    # 5. 新增：配置防火墙
    echo ">>> [4/6] 正在配置防火墙..."
    if command -v ufw >/dev/null 2>&1; then
        ufw allow $PORT/tcp
        echo ">>> 已添加 UFW 规则以放行端口 $PORT。"
    elif command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port=$PORT/tcp
        firewall-cmd --reload
        echo ">>> 已添加 firewalld 规则以放行端口 $PORT。"
    else
        echo ">>> 未检测到 UFW 或 firewalld，请手动配置防火墙以放行TCP端口 $PORT。"
    fi

    # 6. 启动服务并设置开机自启
    echo ">>> [5/6] 正在启动 danted 服务并设置开机自启..."
    if systemctl restart danted 2>/dev/null && systemctl enable danted 2>/dev/null; then
        echo ">>> danted 服务已启动。"
    else
        echo ">>> 警告：服务启动可能有问题，继续检查状态..."
    fi

    # 7. 监控并确认服务状态
    echo ">>> [6/6] 正在检查服务运行状态..."
    # 等待服务完全启动，但减少等待时间
    sleep 0.5

    # 重试机制：最多尝试3次检查服务状态
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
            echo ">>> 第 $retry_count 次检查失败，重试中..."
            sleep 1
        fi
    done

    if [ "$service_running" = true ]; then
        # 获取公网IP，使用超时机制
        PUBLIC_IP=$(timeout 5 curl -s http://ipv4.icanhazip.com/ 2>/dev/null || echo "获取失败")
        echo ""
        echo -e "${BOLD}${GREEN}================================================================${NC}"
        echo -e "${BOLD}${WHITE}                  >> SOCKS5 代理安装成功！ <<                ${NC}"
        echo -e "${BOLD}${GREEN}================================================================${NC}"
        echo -e "${BOLD}${WHITE}  连接信息: socks5://$PUBLIC_IP:$PORT                     ${NC}"
        echo -e "${BOLD}${WHITE}  认证方式: 系统用户密码 (如 root 或你创建的普通用户)    ${NC}"
        echo -e "${BOLD}${WHITE}  服务状态: 运行中                                         ${NC}"
        echo -e "${BOLD}${GREEN}================================================================${NC}"
    else
        echo ""
        echo -e "${BOLD}${RED}================================================================${NC}"
        echo -e "${BOLD}${WHITE}                  >> SOCKS5 服务启动失败！ <<                  ${NC}"
        echo -e "${BOLD}${RED}================================================================${NC}"
        echo -e "${BOLD}${WHITE}  请运行以下命令查看详细错误日志：                         ${NC}"
        echo -e "${BOLD}${WHITE}     journalctl -u danted --no-pager -l                     ${NC}"
        echo -e "${BOLD}${WHITE}  或检查配置文件：                                         ${NC}"
        echo -e "${BOLD}${WHITE}     cat /etc/danted.conf                                     ${NC}"
        echo -e "${BOLD}${RED}================================================================${NC}"
    fi
}

# Uninstall Dante
uninstall_dante() {
    echo
    read -p "确定是否卸载 SOCKS5 代理? 这会删除所有相关配置.  [y/N]: " choice
    case "$choice" in
      y|Y )
        echo "===== 开始卸载 SOCKS5 代理 ====="

        local port=$(grep -oP 'port = \K\d+' /etc/danted.conf || echo "")

        # Stop and disable service
        if systemctl list-unit-files | grep -q 'danted.service'; then
            echo ">>> [1/4] 停止并禁用 danted 服务... "
            systemctl stop danted || true
            systemctl disable danted || true
        fi

        # Close firewall port
        if [ ! -z "$port" ]; then
            echo ">>> [2/4] 关闭防火墙端口  $port..."
            if command -v ufw >/dev/null 2>&1; then
                ufw delete allow $port/tcp
            elif command -v firewall-cmd >/dev/null 2>&1; then
                firewall-cmd --permanent --remove-port=$port/tcp
                firewall-cmd --reload
            fi
        fi

        # Uninstall package
        echo ">>> [3/4] 卸载 dante-server 软件包..."
        if [ -x "$(command -v apt-get)" ]; then
            apt-get purge -y dante-server > /dev/null
        elif [ -x "$(command -v yum)" ]; then
            yum remove -y dante-server > /dev/null
        fi

        # Clean up remaining files
        echo ">>> [4/4] 删除残留配置文件..."
        rm -f /etc/danted.conf*
        rm -f /etc/pam.d/danted

        echo
        echo "SOCKS5 代理已成功卸载."
        ;;
      * )
        echo "操作取消。"
        ;;
    esac
}

# 安装和配置 Squid HTTP 代理
install_squid() {
    echo
    echo "===== 开始安装 HTTP 代理 ====="
    read -p "输入 HTTP proxy 端口 [默认: 8888]: " PORT
    PORT=${PORT:-8888}

    read -p "输入 proxy 用户名 [默认: user]: " USER
    USER=${USER:-user}

    read -p "输入 proxy 密码 [默认: password123]: " PASS
    PASS=${PASS:-password123}

    echo
    echo ">>> [1/4] 安装 Squid 和授权工具..."
    if [ -x "$(command -v apt-get)" ]; then
        apt_smart_update_if_needed
        measure "squid+auth 工具安装" apt_fast_install squid apache2-utils
    elif [ -x "$(command -v yum)" ]; then
        yum_fast_makecache
        measure "squid+auth 工具安装(yum)" yum_fast_install squid httpd-tools
    else
        echo "错误：不支持的操作系统。仅支持 Debian/Ubuntu 和 CentOS/RHEL"
        exit 1
    fi

    echo ">>> [2/4] Configuring Squid..."
    # 备份原始配置文件
    cp /etc/squid/squid.conf /etc/squid/squid.conf.backup

    # 创建简单配置文件
    cat > /etc/squid/squid.conf << EOF
# Squid HTTP proxy configuration file
http_port $PORT

# Access control
acl localnet src 0.0.0.0/0
acl SSL_ports port 443
acl Safe_ports port 80 21 443 70 210 1025-65535 280 488 591 777
acl CONNECT method CONNECT

# Basic authentication configuration
auth_param basic program /usr/lib/squid3/basic_ncsa_auth /etc/squid/passwd
auth_param basic children 5
auth_param basic realm Squid proxy-caching web server
auth_param basic credentialsttl 2 hours
acl authenticated proxy_auth REQUIRED

# Access rules
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow localhost manager
http_access deny manager
http_access allow authenticated
http_access allow localnet
http_access allow localhost
http_access deny all

# Cache configuration
cache_dir ufs /var/spool/squid 100 16 256
coredump_dir /var/spool/squid

# Log configuration
access_log /var/log/squid/access.log squid
cache_log /var/log/squid/cache.log

# Other configuration
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320

# Disable Via header to improve anonymity
via off
forwarded_for off
EOF

    echo ">>> [3/4] 创建授权 ..."
    htpasswd -cb /etc/squid/passwd "$USER" "$PASS"
    chown proxy:proxy /etc/squid/passwd
    chmod 640 /etc/squid/passwd

    # 保存密码到临时文件供状态检查使用
    echo "$PASS" > /tmp/squid_password
    chmod 600 /tmp/squid_password

    # 同时保存到持久化位置
    echo "$PASS" > /etc/squid/.password
    chmod 600 /etc/squid/.password
    chown proxy:proxy /etc/squid/.password 2>/dev/null || true

    echo ">>> [4/4] 启动服务并设置开机自启..."
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
    echo ">>> 检查 Squid 服务状态..."
    sleep 1

    # Retry mechanism to check service status
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
            echo ">>> Check $retry_count failed, retrying..."
            sleep 1
        fi
    done

    if [ "$service_running" = true ]; then
        PUBLIC_IP=$(timeout 5 curl -s http://ipv4.icanhazip.com/ 2>/dev/null || echo "FAILED")
        echo ""
        echo -e "${BOLD}${GREEN}================================================================${NC}"
        echo -e "${BOLD}${WHITE}                  >> HTTP 代理安装成功！ <<                 ${NC}"
        echo -e "${BOLD}${GREEN}================================================================${NC}"
        echo -e "${BOLD}${WHITE}  连接信息: http://$PUBLIC_IP:$PORT                         ${NC}"
        echo -e "${BOLD}${WHITE}  用户名: $USER                                            ${NC}"
        echo -e "${BOLD}${WHITE}  密码: $PASS                                              ${NC}"
        echo -e "${BOLD}${WHITE}  服务状态: 运行中                                         ${NC}"
        echo -e "${BOLD}${GREEN}================================================================${NC}"
    else
        echo ""
        echo -e "${BOLD}${RED}================================================================${NC}"
        echo -e "${BOLD}${WHITE}                    >> HTTP 服务启动失败！ <<                        ${NC}"
        echo -e "${BOLD}${RED}================================================================${NC}"
        echo -e "${BOLD}${WHITE}     请运行以下命令查看详细错误日志：                           ${NC}"
        echo -e "${BOLD}${WHITE}     journalctl -u squid --no-pager -l                        ${NC}"
        echo -e "${BOLD}${WHITE}     或检查配置文件：                                          ${NC}"
        echo -e "${BOLD}${WHITE}     cat /etc/squid/squid.conf                                ${NC}"
        echo -e "${BOLD}${RED}================================================================${NC}"
    fi
}

# 卸载 Squid HTTP 代理
uninstall_squid() {
    echo
    read -p "确定是否卸载 HTTP 代理? 这会删除所有相关配置. [y/N]: " choice
    case "$choice" in
      y|Y )
        echo "===== 开始卸载 HTTP 代理 ====="

        local port=$(grep -oP 'http_port\s+\K\d+' /etc/squid/squid.conf || echo "")

        # 停止并禁用服务
        if systemctl list-unit-files | grep -q 'squid.service'; then
            echo ">>> [1/4] 停止并禁用 squid service..."
            systemctl stop squid || true
            systemctl disable squid || true
        fi

        # 关闭防火墙端口
        if [ ! -z "$port" ]; then
            echo ">>> [2/4] 关闭防火墙端口 $port..."
            if command -v ufw >/dev/null 2>&1; then
                ufw delete allow $port/tcp || true
            elif command -v firewall-cmd >/dev/null 2>&1; then
                firewall-cmd --permanent --remove-port=$port/tcp || true
                firewall-cmd --reload || true
            fi
        fi

        # 卸载软件包
        echo ">>> [3/4] 卸载 squid 软件包..."
        if [ -x "$(command -v apt-get)" ]; then
            apt-get remove --purge -y squid
        elif [ -x "$(command -v yum)" ]; then
            yum remove -y squid
        fi

        # 清理残留文件
        echo ">>> [4/4] 清理配置文件..."
        rm -rf /etc/squid
        rm -rf /var/spool/squid
        rm -rf /var/log/squid

        echo
        echo "============================================"
        echo " HTTP proxy 成功卸载!"
        echo "============================================"
        ;;
      * )
        echo "操作取消."
        ;;
    esac
}

# --- Main Logic ---

# Check root privileges at script start
check_root

# Main menu loop
while true; do
    check_status
    echo -e "${BOLD}${YELLOW}>> 请选择您要执行的操作:${NC}"
    echo ""
    echo -e "${CYAN}+---------------------------------------------------------------+${NC}"
    echo -e " ${BLUE}[SOCKS5 代理管理]${NC}"
    echo -e "  ${WHITE}1)${NC} ${GREEN}安装 SOCKS5 代理${NC}"
    echo -e "  ${WHITE}2)${NC} ${RED}卸载 SOCKS5 代理${NC}"
    echo -e "${CYAN}+---------------------------------------------------------------+${NC}"
    echo ""
    echo -e "${CYAN}+---------------------------------------------------------------+${NC}"
    echo -e "${NC} ${BLUE}[HTTP 代理管理]${NC}                                          ${NC}"
    echo -e "${NC}  ${WHITE}3)${NC} ${GREEN}安装 HTTP 代理${NC}                                 ${NC}"
    echo -e "${NC}  ${WHITE}4)${NC} ${RED}卸载 HTTP 代理${NC}                                 ${NC}"
    echo -e "${CYAN}+---------------------------------------------------------------+${NC}"
    echo ""
    echo -e "${CYAN}+---------------------------------------------------------------+${NC}"
    echo -e "${NC}  ${WHITE}0)${NC} ${BOLD}退出脚本${NC}                                               ${NC}"
    echo -e "${CYAN}+---------------------------------------------------------------+${NC}"
    echo
    read -p "请输入选项 [0-4]: " main_choice

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
        0)
            echo "退出脚本。"
            exit 0
            ;;
        *)
            echo "无效输入，请输入 0-4 之间的数字。"
            ;;
    esac
    echo
    read -p "按 [Enter] 键返回主菜单..."
done
