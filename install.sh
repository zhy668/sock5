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
    echo "--------------------------------------------"
    echo "当前 SOCKS5 (Dante) 服务状态:"
    if ! systemctl list-unit-files | grep -q 'danted.service'; then
        echo "  状态: 未安装"
    elif systemctl is-active --quiet danted; then
        local port=$(grep -oP 'port = \K\d+' /etc/danted.conf || echo "未知")
        echo "  状态: ✅ 已安装并正在运行 (Active)"
        echo "  监听端口: $port"
    else
        echo "  状态: ❌ 已安装但未运行 (Inactive/Dead)"
        echo "  请尝试重新安装或检查日志: 'journalctl -u danted'"
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

# --- 主逻辑 ---

# 脚本开始时，先检查root权限
check_root

# 主菜单循环
while true; do
    check_status
    echo "请选择您要执行的操作:"
    echo "  1) 安装 SOCKS5 (Dante) 代理"
    echo "  2) 卸载 SOCKS5 (Dante) 代理"
    echo "  0) 退出脚本"
    read -p "请输入选项 [0-2]: " main_choice

    case $main_choice in
        1)
            install_dante
            ;;
        2)
            uninstall_dante
            ;;
        0)
            echo "退出脚本。"
            exit 0
            ;;
        *)
            echo "无效输入，请输入 0, 1 或 2。"
            ;;
    esac
    echo
    read -p "按 [Enter] 键返回主菜单..."
done