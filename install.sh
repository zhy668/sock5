#!/bin/bash

# 确保脚本在发生错误时退出
set -e

# --- 全局函数定义 ---

# 检查是否以root用户运行
check_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "错误：本脚本需要以 root 权限运行。"
    echo "请尝试使用 'sudo ./your_script_name.sh' 来运行。"
    exit 1
  fi
}

# 检查并显示当前服务状态
check_status() {
    echo "============================================"
    echo "     HTTP & SOCKS5 代理管理脚本"
    echo "============================================"
    echo "当前服务状态:"

    # 检查SOCKS5 (Dante)状态
    if ! systemctl list-unit-files | grep -q 'danted.service'; then
        echo "  - SOCKS5 (Dante): ❌ 未安装"
    elif systemctl is-active --quiet danted; then
        local socks_port=$(grep -oP 'port = \K\d+' /etc/danted.conf || echo "未知")
        local public_ip=$(curl -s http://ipv4.icanhazip.com/ || curl -s http://checkip.amazonaws.com/ || echo "未知")
        echo "  - SOCKS5 (Dante): ✅ 运行中"
        echo "    连接信息: socks5:$public_ip:$socks_port:root:[系统用户密码]"
    else
        echo "  - SOCKS5 (Dante): ❌ 已安装但未运行"
    fi

    # 检查HTTP (Squid)状态
    if systemctl is-active --quiet squid; then
        local http_port=$(grep -oP 'http_port\s+\K\d+' /etc/squid/squid.conf || echo "未知")
        local public_ip=$(curl -s http://ipv4.icanhazip.com/ || curl -s http://checkip.amazonaws.com/ || echo "未知")
        local http_user="未知"
        local http_pass="[已设置]"

        # 尝试从认证文件中获取用户名
        if [ -f "/etc/squid/passwd" ]; then
            http_user=$(cut -d: -f1 /etc/squid/passwd | head -1)
        fi

        echo "  - HTTP (Squid): ✅ 运行中"
        echo "    连接信息: http:$public_ip:$http_port:$http_user:$http_pass"
    else
        echo "  - HTTP (Squid): ❌ 未安装或未运行"
    fi
    echo "--------------------------------------------"
}

# 安装和配置 Dante
install_dante() {
    echo
    echo "===== 开始安装 SOCKS5 (Dante) 代理 ====="

    # 1. 获取用户输入的端口
    read -p "请输入SOCKS5代理要使用的端口 [默认 8087]: " PORT
    PORT=${PORT:-8087}
    echo

    # 2. 安装 dante-server
    echo ">>> [1/6] 正在安装 dante-server..."
    if [ -x "$(command -v apt-get)" ]; then
        apt-get update > /dev/null
        apt-get install -y dante-server
    elif [ -x "$(command -v yum)" ]; then
        yum install -y epel-release
        yum install -y dante-server
    else
        echo "错误：不支持的操作系统。请在 Debian/Ubuntu/CentOS 上运行。"
        exit 1
    fi
    echo ">>> dante-server 安装完成。"

    # 3. 配置PAM认证
    echo ">>> [2/6] 正在配置PAM认证模块..."
    PAM_CONF="/etc/pam.d/danted"
    tee $PAM_CONF > /dev/null <<EOF
#%PAM-1.0
auth       required   pam_unix.so
account    required   pam_unix.so
EOF
    echo ">>> PAM配置完成。"

    # 4. 写入 dante-server 配置文件
    echo ">>> [3/6] 正在生成 danted.conf 配置文件..."
    IFACE=$(ip route get 8.8.8.8 | grep -oP 'dev \K\S+')
    CONF="/etc/danted.conf"
    [ -f $CONF ] && mv $CONF "$CONF.bak.$(date +%F-%T)"
    tee $CONF > /dev/null <<EOF
logoutput: syslog

# 关键修改：监听在所有IPv4接口上，而不是仅限内网IP
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
    systemctl restart danted
    systemctl enable danted
    echo ">>> danted 服务已启动。"

    # 7. 监控并确认服务状态
    echo ">>> [6/6] 正在检查服务运行状态..."
    sleep 1
    if systemctl is-active --quiet danted; then
        PUBLIC_IP=$(curl -s http://ipv4.icanhazip.com/)
        echo
        echo "============================================"
        echo "✅ SOCKS5 代理已成功安装并启动！"
        echo "--------------------------------------------"
        echo "连接信息: SOCKS5:$PUBLIC_IP:$PORT:root:[系统用户密码]"
        echo "认证方式: 使用您VPS的系统用户和密码 (如 'root')"
        echo "============================================"
    else
        echo
        echo "============================================"
        echo "❌ 错误：danted 服务启动失败！"
        echo "请运行 'journalctl -u danted' 命令查看详细错误日志。"
        echo "============================================"
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
        apt-get update > /dev/null
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
    sleep 2
    if systemctl is-active --quiet squid; then
        PUBLIC_IP=$(curl -s http://ipv4.icanhazip.com/)
        echo
        echo "============================================"
        echo "✅ HTTP 代理已成功安装并启动！"
        echo "--------------------------------------------"
        echo "连接信息: http:$PUBLIC_IP:$PORT:$USER:$PASS"
        echo "============================================"
    else
        echo
        echo "============================================"
        echo "❌ 错误：Squid 服务启动失败！"
        echo "请运行 'journalctl -u squid' 命令查看详细错误日志。"
        echo "============================================"
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
        echo "✅ HTTP (Squid) 代理已成功卸载！"
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
    echo "请选择您要执行的操作:"
    echo
    echo "=== SOCKS5 代理管理 ==="
    echo "  1) 安装 SOCKS5 (Dante) 代理"
    echo "  2) 卸载 SOCKS5 (Dante) 代理"
    echo
    echo "=== HTTP 代理管理 ==="
    echo "  3) 安装 HTTP (Squid) 代理"
    echo "  4) 卸载 HTTP (Squid) 代理"
    echo
    echo "=== 其他选项 ==="
    echo "  0) 退出脚本"
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
