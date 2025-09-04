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
    local public_ip=$(curl -s http://ipv4.icanhazip.com/ 2>/dev/null || echo "获取失败")

    echo "============================================"
    echo "代理服务器状态总览"
    echo "============================================"
    echo "服务器IP: $public_ip"
    echo

    # SOCKS5 (Dante) 状态检查
    echo "--------------------------------------------"
    echo "SOCKS5 (Dante) 代理状态:"
    if ! systemctl list-unit-files | grep -q 'danted.service'; then
        echo "  状态: 未安装"
    elif systemctl is-active --quiet danted; then
        local socks_port=$(grep -oP 'port = \K\d+' /etc/danted.conf 2>/dev/null || echo "未知")
        echo "  状态: ✅ 已安装并正在运行 (Active)"
        echo "  连接信息:"
        echo "    - 服务器: $public_ip"
        echo "    - 端口: $socks_port"
        echo "    - 协议: SOCKS5"
        echo "    - 认证: 系统用户认证 (如: root用户)"
    else
        echo "  状态: ❌ 已安装但未运行 (Inactive/Dead)"
        echo "  请尝试重新安装或检查日志: 'journalctl -u danted'"
    fi

    # HTTP (Tinyproxy) 状态检查
    echo "--------------------------------------------"
    echo "HTTP (Tinyproxy) 代理状态:"
    if ! systemctl list-unit-files | grep -q 'tinyproxy.service'; then
        echo "  状态: 未安装"
    elif systemctl is-active --quiet tinyproxy; then
        local http_port=$(grep -oP '^Port \K\d+' /etc/tinyproxy/tinyproxy.conf 2>/dev/null || echo "未知")
        local http_user=""
        local http_pass=""
        if [ -f "/etc/tinyproxy/tinyproxy.passwd" ]; then
            http_user=$(cut -d: -f1 /etc/tinyproxy/tinyproxy.passwd 2>/dev/null || echo "未知")
            http_pass="[已设置]"
        fi
        echo "  状态: ✅ 已安装并正在运行 (Active)"
        echo "  连接信息:"
        echo "    - 服务器: $public_ip"
        echo "    - 端口: $http_port"
        echo "    - 协议: HTTP"
        # 检查配置文件中是否有BasicAuth配置
        if [ -f "/etc/tinyproxy/tinyproxy.conf" ] && grep -q "^BasicAuth" /etc/tinyproxy/tinyproxy.conf; then
            auth_line=$(grep "^BasicAuth" /etc/tinyproxy/tinyproxy.conf)
            auth_user=$(echo $auth_line | awk '{print $2}')
            echo "    - 认证: BasicAuth认证"
            echo "    - 用户名: $auth_user"
        else
            echo "    - 认证: 无需认证"
        fi
    else
        echo "  状态: ❌ 已安装但未运行 (Inactive/Dead)"
        echo "  请尝试重新安装或检查日志: 'journalctl -u tinyproxy'"
    fi
    echo "============================================"
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
        echo "服务器IP: $PUBLIC_IP"
        echo "端口: $PORT"
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

# 检测系统架构
detect_architecture() {
    local arch=$(uname -m)
    case $arch in
        x86_64)
            echo "amd64"
            ;;
        aarch64)
            echo "arm64"
            ;;
        armv7l)
            echo "armv7"
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

# 下载预编译的tinyproxy二进制文件
download_precompiled_tinyproxy() {
    local arch=$(detect_architecture)
    local github_api="https://api.github.com/repos/zhy668/sock5/releases"

    echo ">>> 检测到系统架构: $arch"

    if [ "$arch" = "unknown" ]; then
        echo ">>> 不支持的架构，将使用源码编译方式"
        return 1
    fi

    echo ">>> 正在获取最新的预编译版本..."

    # 获取最新release的下载链接
    local download_url=$(curl -s "$github_api" | grep -o "https://github.com/zhy668/sock5/releases/download/[^\"]*tinyproxy-$arch" | head -1)

    if [ -z "$download_url" ]; then
        echo ">>> 未找到预编译版本，将使用源码编译方式"
        return 1
    fi

    echo ">>> 正在下载预编译的tinyproxy二进制文件..."
    if wget -q "$download_url" -O /usr/bin/tinyproxy; then
        chmod +x /usr/bin/tinyproxy
        echo ">>> 预编译版本下载安装完成"
        return 0
    else
        echo ">>> 下载失败，将使用源码编译方式"
        return 1
    fi
}

# 源码编译安装tinyproxy（备用方案）
compile_tinyproxy_from_source() {
    echo ">>> 开始源码编译安装..."

    # 安装编译依赖
    echo ">>> 正在安装编译依赖..."
    if [ -x "$(command -v apt-get)" ]; then
        apt-get update > /dev/null
        apt-get install -y build-essential autoconf automake libtool git wget > /dev/null
    elif [ -x "$(command -v yum)" ]; then
        yum groupinstall -y "Development Tools" > /dev/null
        yum install -y autoconf automake libtool git wget > /dev/null
    else
        echo "错误：不支持的操作系统。请在 Debian/Ubuntu/CentOS 上运行。"
        return 1
    fi
    echo ">>> 编译依赖安装完成。"

    # 下载源码
    echo ">>> 正在下载 Tinyproxy 源码..."
    cd /tmp
    rm -rf tinyproxy
    if ! git clone https://github.com/tinyproxy/tinyproxy.git > /dev/null 2>&1; then
        echo "错误：无法从GitHub下载源码。请检查网络连接。"
        return 1
    fi
    echo ">>> 源码下载完成。"

    # 编译安装
    echo ">>> 正在编译 Tinyproxy（这可能需要几分钟）..."
    cd tinyproxy
    ./autogen.sh > /dev/null 2>&1
    if ! ./configure --prefix=/usr --sysconfdir=/etc/tinyproxy --enable-upstream --enable-transparent > /dev/null 2>&1; then
        echo "错误：配置编译环境失败。"
        return 1
    fi

    if ! make > /dev/null 2>&1; then
        echo "错误：编译失败。"
        return 1
    fi

    if ! make install > /dev/null 2>&1; then
        echo "错误：安装失败。"
        return 1
    fi
    echo ">>> Tinyproxy 源码编译安装完成。"

    # 清理临时文件
    cd /
    rm -rf /tmp/tinyproxy

    return 0
}

# 安装和配置 Tinyproxy
install_tinyproxy() {
    echo
    echo "===== 开始安装 HTTP (Tinyproxy) 代理 ====="

    # 1. 获取用户输入的端口和认证信息
    read -p "请输入HTTP代理要使用的端口 [默认 8088]: " HTTP_PORT
    HTTP_PORT=${HTTP_PORT:-8088}
    echo

    read -p "是否启用用户名密码认证？[y/N]: " enable_auth
    HTTP_USER=""
    HTTP_PASS=""
    if [[ "$enable_auth" =~ ^[Yy]$ ]]; then
        read -p "请输入HTTP代理用户名: " HTTP_USER
        read -s -p "请输入HTTP代理密码: " HTTP_PASS
        echo
        if [ -z "$HTTP_USER" ] || [ -z "$HTTP_PASS" ]; then
            echo "错误：用户名和密码不能为空。"
            return 1
        fi
    fi
    echo

    # 2. 尝试下载预编译版本，失败则源码编译
    echo ">>> [1/7] 正在安装 Tinyproxy..."
    if ! download_precompiled_tinyproxy; then
        if ! compile_tinyproxy_from_source; then
            echo "错误：Tinyproxy 安装失败。"
            return 1
        fi
    fi

    # 3. 创建配置目录和文件
    echo ">>> [2/7] 正在生成配置文件..."
    mkdir -p /etc/tinyproxy
    mkdir -p /var/log/tinyproxy
    mkdir -p /run/tinyproxy

    # 创建tinyproxy用户
    if ! id "tinyproxy" &>/dev/null; then
        useradd -r -s /bin/false tinyproxy
    fi

    # 设置目录权限
    chown tinyproxy:tinyproxy /var/log/tinyproxy
    chown tinyproxy:tinyproxy /run/tinyproxy

    # 生成主配置文件
    TINYPROXY_CONF="/etc/tinyproxy/tinyproxy.conf"
    if [ ! -z "$HTTP_USER" ]; then
        echo ">>> [3/7] 正在配置用户认证..."
        # 生成带认证的配置文件
        tee $TINYPROXY_CONF > /dev/null <<EOF
# Tinyproxy 配置文件
User tinyproxy
Group tinyproxy

Port $HTTP_PORT
Listen 0.0.0.0

Timeout 600
LogFile "/var/log/tinyproxy/tinyproxy.log"
LogLevel Info
PidFile "/run/tinyproxy/tinyproxy.pid"

MaxClients 100

# 允许所有IP访问
Allow 0.0.0.0/0

# 禁用Via头部以提高匿名性
DisableViaHeader Yes

# 允许的连接端口
ConnectPort 443
ConnectPort 563
ConnectPort 80

# 启用基本认证
BasicAuth $HTTP_USER $HTTP_PASS
EOF
        echo ">>> 用户认证配置完成。"
    else
        echo ">>> [3/7] 跳过用户认证配置（未启用）。"
        # 生成无认证的配置文件
        tee $TINYPROXY_CONF > /dev/null <<EOF
# Tinyproxy 配置文件
User tinyproxy
Group tinyproxy

Port $HTTP_PORT
Listen 0.0.0.0

Timeout 600
LogFile "/var/log/tinyproxy/tinyproxy.log"
LogLevel Info
PidFile "/run/tinyproxy/tinyproxy.pid"

MaxClients 100

# 允许所有IP访问
Allow 0.0.0.0/0

# 禁用Via头部以提高匿名性
DisableViaHeader Yes

# 允许的连接端口
ConnectPort 443
ConnectPort 563
ConnectPort 80
EOF
    fi

    echo ">>> 配置文件生成完成。"

    # 4. 创建systemd服务文件
    echo ">>> [4/7] 正在创建 systemd 服务..."
    TINYPROXY_SERVICE="/etc/systemd/system/tinyproxy.service"
    tee $TINYPROXY_SERVICE > /dev/null <<EOF
[Unit]
Description=Tinyproxy HTTP proxy daemon
Documentation=man:tinyproxy(8)
After=network.target

[Service]
Type=forking
User=tinyproxy
Group=tinyproxy
ExecStart=/usr/bin/tinyproxy -c /etc/tinyproxy/tinyproxy.conf
ExecReload=/bin/kill -HUP \$MAINPID
PIDFile=/run/tinyproxy/tinyproxy.pid
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    echo ">>> systemd 服务创建完成。"

    # 5. 配置防火墙
    echo ">>> [5/7] 正在配置防火墙..."
    if command -v ufw >/dev/null 2>&1; then
        ufw allow $HTTP_PORT/tcp > /dev/null
        echo ">>> 已添加 UFW 规则以放行端口 $HTTP_PORT。"
    elif command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port=$HTTP_PORT/tcp > /dev/null
        firewall-cmd --reload > /dev/null
        echo ">>> 已添加 firewalld 规则以放行端口 $HTTP_PORT。"
    else
        echo ">>> 未检测到 UFW 或 firewalld，请手动配置防火墙以放行TCP端口 $HTTP_PORT。"
    fi

    # 6. 启动服务并设置开机自启
    echo ">>> [6/7] 正在启动 tinyproxy 服务并设置开机自启..."
    systemctl restart tinyproxy
    systemctl enable tinyproxy > /dev/null
    echo ">>> tinyproxy 服务已启动。"

    # 7. 检查服务状态并显示结果
    sleep 2
    if systemctl is-active --quiet tinyproxy; then
        PUBLIC_IP=$(curl -s http://ipv4.icanhazip.com/)
        echo
        echo "============================================"
        echo "✅ HTTP 代理已成功安装并启动！"
        echo "--------------------------------------------"
        echo "服务器IP: $PUBLIC_IP"
        echo "端口: $HTTP_PORT"
        echo "协议: HTTP"
        if [ ! -z "$HTTP_USER" ]; then
            echo "用户名: $HTTP_USER"
            echo "密码: $HTTP_PASS"
        else
            echo "认证: 无需认证"
        fi
        echo "============================================"
    else
        echo
        echo "============================================"
        echo "❌ 错误：tinyproxy 服务启动失败！"
        echo "请运行 'journalctl -u tinyproxy' 命令查看详细错误日志。"
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

# 卸载 Tinyproxy
uninstall_tinyproxy() {
    echo
    read -p "您确定要卸载 HTTP (Tinyproxy) 代理吗？这将删除所有配置和编译文件。[y/N]: " choice
    case "$choice" in
      y|Y )
        echo "===== 开始卸载 HTTP (Tinyproxy) 代理 ====="

        local http_port=$(grep -oP '^Port \K\d+' /etc/tinyproxy/tinyproxy.conf 2>/dev/null || echo "")

        # 停止并禁用服务
        if systemctl list-unit-files | grep -q 'tinyproxy.service'; then
            echo ">>> [1/6] 正在停止并禁用 tinyproxy 服务..."
            systemctl stop tinyproxy 2>/dev/null || true
            systemctl disable tinyproxy 2>/dev/null || true
        fi

        # 关闭防火墙端口
        if [ ! -z "$http_port" ]; then
            echo ">>> [2/6] 正在关闭防火墙端口 $http_port..."
            if command -v ufw >/dev/null 2>&1; then
                ufw delete allow $http_port/tcp 2>/dev/null || true
            elif command -v firewall-cmd >/dev/null 2>&1; then
                firewall-cmd --permanent --remove-port=$http_port/tcp 2>/dev/null || true
                firewall-cmd --reload 2>/dev/null || true
            fi
        fi

        # 删除systemd服务文件
        echo ">>> [3/6] 正在删除 systemd 服务文件..."
        rm -f /etc/systemd/system/tinyproxy.service
        systemctl daemon-reload

        # 删除编译安装的文件
        echo ">>> [4/6] 正在删除编译安装的文件..."
        rm -f /usr/bin/tinyproxy
        rm -f /usr/share/man/man8/tinyproxy.8*
        rm -rf /usr/share/tinyproxy

        # 清理配置文件和日志
        echo ">>> [5/6] 正在清理配置文件和日志..."
        rm -rf /etc/tinyproxy
        rm -rf /var/log/tinyproxy
        rm -rf /run/tinyproxy

        # 删除用户
        echo ">>> [6/6] 正在删除 tinyproxy 用户..."
        if id "tinyproxy" &>/dev/null; then
            userdel tinyproxy 2>/dev/null || true
        fi

        echo
        echo "✅ HTTP (Tinyproxy) 代理已成功卸载。"
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
    echo
    echo "请选择您要执行的操作:"
    echo "  === SOCKS5 代理管理 ==="
    echo "  1) 安装 SOCKS5 (Dante) 代理"
    echo "  2) 卸载 SOCKS5 (Dante) 代理"
    echo
    echo "  === HTTP 代理管理 ==="
    echo "  3) 安装 HTTP (Tinyproxy) 代理"
    echo "  4) 卸载 HTTP (Tinyproxy) 代理"
    echo
    echo "  === 其他选项 ==="
    echo "  0) 退出脚本"
    read -p "请输入选项 [0-4]: " main_choice

    case $main_choice in
        1)
            install_dante
            ;;
        2)
            uninstall_dante
            ;;
        3)
            install_tinyproxy
            ;;
        4)
            uninstall_tinyproxy
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