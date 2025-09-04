#!/bin/bash

# 修复tinyproxy配置文件的脚本

echo "正在修复tinyproxy配置文件..."

# 停止服务
systemctl stop tinyproxy 2>/dev/null || true

# 获取当前端口
HTTP_PORT=$(grep -oP '^Port \K\d+' /etc/tinyproxy/tinyproxy.conf 2>/dev/null || echo "8088")

# 重新生成配置文件
cat > /etc/tinyproxy/tinyproxy.conf <<EOF
# Tinyproxy 配置文件
User tinyproxy
Group tinyproxy

Port $HTTP_PORT
Listen 0.0.0.0

Timeout 600
LogFile "/var/log/tinyproxy/tinyproxy.log"
LogLevel Info
PidFile "/var/run/tinyproxy/tinyproxy.pid"

MaxClients 100
MinSpareServers 5
MaxSpareServers 20
StartServers 10
MaxRequestsPerChild 0

# 允许所有IP访问
Allow 0.0.0.0/0

# 禁用Via头部以提高匿名性
DisableViaHeader Yes

# 允许的连接端口
ConnectPort 443
ConnectPort 563
ConnectPort 80
EOF

# 如果存在认证文件，添加认证配置
if [ -f "/etc/tinyproxy/tinyproxy.passwd" ]; then
    echo "" >> /etc/tinyproxy/tinyproxy.conf
    echo "# 启用基本认证" >> /etc/tinyproxy/tinyproxy.conf
    echo "BasicAuth /etc/tinyproxy/tinyproxy.passwd" >> /etc/tinyproxy/tinyproxy.conf
fi

# 确保目录权限正确
chown tinyproxy:tinyproxy /var/log/tinyproxy 2>/dev/null || true
chown tinyproxy:tinyproxy /var/run/tinyproxy 2>/dev/null || true

# 重启服务
systemctl daemon-reload
systemctl restart tinyproxy

# 检查状态
sleep 2
if systemctl is-active --quiet tinyproxy; then
    echo "✅ tinyproxy 配置修复成功，服务正在运行"
    echo "端口: $HTTP_PORT"
    if [ -f "/etc/tinyproxy/tinyproxy.passwd" ]; then
        echo "认证: 已启用"
        echo "用户名: $(cut -d: -f1 /etc/tinyproxy/tinyproxy.passwd)"
    else
        echo "认证: 未启用"
    fi
else
    echo "❌ 服务启动失败，请检查日志:"
    echo "journalctl -u tinyproxy --no-pager -l"
fi
