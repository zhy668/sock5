#!/bin/bash
#
# =================================================================
#            独立的 HTTP/HTTPS 代理 (Squid) 管理脚本
# =================================================================
#
#       功能: 在 Debian, Ubuntu, CentOS 系统上一键安装、
#             卸载并管理一个带有密码认证的、安全的Squid代理。
#
# =================================================================

# 确保脚本在任何命令出错时立即退出，保证安全性
set -e

# --- 核心功能函数 ---

# 检查是否以root用户运行
check_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "错误：本脚本必须以 root 权限运行。"
    echo "请尝试使用 'sudo ./http_install.sh' 来执行。"
    exit 1
  fi
}

# 检查并显示Squid服务的当前状态
check_status() {
    echo "============================================"
    echo "     HTTP/HTTPS 代理 (Squid) 管理脚本"
    echo "============================================"
    echo "当前服务状态:"
    
    # 通过systemctl安静模式检查服务是否正在运行
    if systemctl is-active --quiet squid; then
        # 如果运行中，则从配置文件中提取端口号
        local squid_port=$(grep -oP 'http_port\s+\S+:(\d+)' /etc/squid/squid.conf || echo "未知")
        echo "  - HTTP (Squid): ✅ 运行中 (端口: $squid_port)"
    else
        echo "  - HTTP (Squid): ❌ 未安装或未运行"
    fi
    echo "--------------------------------------------"
}

# 安装并配置Squid
install_squid() {
    echo
    echo "===== 开始安装 HTTP (Squid) 代理 ====="
    read -p "请输入HTTP代理端口 [默认: 8888]: " PORT
    PORT=${PORT:-8888}

    read -p "请输入代理用户名 [默认: zhy668]: " USER
    USER=${USER:-zhy668}

    read -sp "请输入代理密码 (必填项): " PASS
    echo
    if [ -z "$PASS" ]; then
        echo "❌ 错误：密码不能为空。"
        return 1
    fi

    echo ">>> [1/4] 正在安装 Squid 和认证工具..."
    if [ -x "$(command -v apt-get)" ]; then
        apt-get update > /dev/null
        apt-get install -y squid apache2-utils
    elif [ -x "$(command -v yum)" ]; then
        yum install -y squid httpd-tools
    else
        echo "❌ 错误：不支持的操作系统。请在 Debian, Ubuntu, 或 CentOS 上运行。"
        exit 1
    fi

    echo ">>> [2/4] 正在创建认证密码文件..."
    # -c 创建新文件, -b 使用批处理模式(非交互式)
    htpasswd -cb /etc/squid/passwd "$USER" "$PASS"
    # Squid在某些系统上以'proxy'用户运行，需确保其有权限读取密码文件
    chown proxy:proxy /etc/squid/passwd

    echo ">>> [3/4] 正在生成极简且安全的 Squid 配置文件..."
    local CONF_FILE="/etc/squid/squid.conf"
    # 备份系统自带的、复杂的原始配置文件
    [ -f "$CONF_FILE" ] && mv "$CONF_FILE" "${CONF_FILE}.bak.$(date +%F)"
    
    # 自动查找认证程序的路径，以兼容不同发行版
    local ncsa_auth_path="/usr/lib/squid/basic_ncsa_auth"
    if [ ! -f "$ncsa_auth_path" ]; then
        ncsa_auth_path=$(find /usr/lib* -name "basic_ncsa_auth" | head -n 1)
    fi
    
    # 使用tee命令写入一个全新的、简洁的配置文件
    tee "$CONF_FILE" > /dev/null <<EOF
# --- 认证配置 ---
# 使用htpasswd文件进行基础认证
auth_param basic program ${ncsa_auth_path} /etc/squid/passwd
# 认证弹窗的提示信息
auth_param basic realm "Squid Proxy - 请输入用户名和密码"
# 认证凭证的有效时间
auth_param basic credentialsttl 2 hours

# --- 访问控制列表 (ACL) ---
# 定义一个名为'authenticated_users'的列表，条件是用户必须通过认证
acl authenticated_users proxy_auth REQUIRED

# --- 访问规则 (核心安全配置) ---
# 仅允许已认证的用户访问
http_access allow authenticated_users
# 拒绝所有其他未经认证的访问请求，防止代理被滥用
http_access deny all

# --- 端口和网络配置 ---
# 在所有网络接口上监听指定端口
http_port 0.0.0.0:${PORT}
# 设置DNS服务器，增强解析能力
dns_nameservers 8.8.8.8 1.1.1.1
# 隐藏主机名，提升安全性
visible_hostname unknown
EOF

    echo ">>> [4/4] 正在配置防火墙并启动 Squid 服务..."
    if command -v ufw >/dev/null; then ufw allow "$PORT"/tcp;
    elif command -v firewall-cmd >/dev/null; then firewall-cmd --permanent --add-port="$PORT"/tcp && firewall-cmd --reload; fi
    
    # 初始化Squid缓存目录，某些系统需要此步骤
    squid -z > /dev/null 2>&1 || true
    
    # 重启并设置开机自启
    systemctl restart squid
    systemctl enable squid

    # 稍作等待，让服务有时间完全启动
    sleep 1 
    if systemctl is-active --quiet squid; then
        PUBLIC_IP=$(curl -s http://ipv4.icanhazip.com/)
        # 使用 -e 参数让 \n (换行符) 生效，格式化输出
        echo -e "\n✅ HTTP (Squid) 代理安装成功！\n" \
                "   - 服务器 IP:  $PUBLIC_IP\n" \
                "   - 端口:       $PORT\n" \
                "   - 用户名:     $USER\n" \
                "   - 密码:       (您刚才输入的密码)\n" \
                "   - 功能:       支持 HTTP 和 HTTPS 网站"
    else
        echo -e "\n❌ Squid 服务启动失败！请运行以下命令查看错误日志:\n" \
                "   journalctl -u squid"
    fi
}

# 彻底卸载Squid及其配置
uninstall_squid() {
    echo
    read -p "您确定要卸载 HTTP (Squid) 代理吗？所有配置都将被删除。[y/N]: " choice
    if [[ "$choice" =~ ^[yY]$ ]]; then
        echo "===== 开始卸载 Squid 代理 ====="
        local port=$(grep -oP 'http_port\s+\S+:(\d+)' /etc/squid/squid.conf || echo "")
        
        systemctl stop squid || true
        systemctl disable squid || true
        
        if [ ! -z "$port" ]; then
            echo ">>> 正在关闭防火墙端口 $port..."
            if command -v ufw >/dev/null; then ufw delete allow "$port"/tcp >/dev/null;
            elif command -v firewall-cmd >/dev/null; then firewall-cmd --permanent --remove-port="$port"/tcp >/dev/null && firewall-cmd --reload >/dev/null; fi
        fi
        
        echo ">>> 正在彻底卸载 Squid 软件包..."
        if [ -x "$(command -v apt-get)" ]; then apt-get purge -y squid squid-common > /dev/null;
        elif [ -x "$(command -v yum)" ]; then yum remove -y squid > /dev/null; fi

        echo ">>> 正在清理配置文件和密码文件..."
        rm -rf /etc/squid/
        
        echo -e "\n✅ HTTP (Squid) 代理已成功卸载。"
    else
        echo "操作已取消。"
    fi
}

# --- 主逻辑 ---

# 脚本启动时，首先检查权限
check_root

# 主菜单无限循环，直到用户选择退出
while true; do
    check_status
    echo "请选择操作:"
    echo "  1) 安装 HTTP 代理 (Squid)"
    echo "  2) 卸载 HTTP 代理 (Squid)"
    echo "  0) 退出脚本"
    read -p "请输入选项 [0-2]: " main_choice

    case $main_choice in
        1)
            install_squid
            ;;
        2)
            uninstall_squid
            ;;
        0)
            echo "正在退出脚本。"
            exit 0
            ;;
        *)
            echo "无效输入，请输入 0, 1, 或 2。"
            ;;
    esac
    echo
    read -p "按 [Enter] 键返回主菜单..."
done