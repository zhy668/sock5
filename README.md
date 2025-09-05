# HTTP & SOCKS5 代理一键管理工具

一个功能全面的代理服务器管理脚本，支持 HTTP (Squid) 和 SOCKS5 (Dante) 代理的一键安装、配置和管理。

## ✨ 特性

- 🚀 **快速安装**: 使用系统包管理器，安装速度快
- 🔧 **双协议支持**: 同时支持 HTTP (Squid) 和 SOCKS5 (Dante) 代理
- 🛡️ **独立认证**: HTTP 使用 htpasswd 认证，SOCKS5 使用系统用户认证
- 📊 **状态监控**: 实时显示代理服务状态和连接信息
- 🔥 **自动配置**: 自动配置防火墙、服务管理等
- 🌐 **多系统支持**: 支持 Ubuntu/Debian/CentOS 系统

## 🚀 快速开始

### SOCKS5 代理一键安装
```bash
bash <(curl -sL https://raw.githubusercontent.com/zhy668/sock5/refs/heads/master/install.sh)
```

### HTTP 代理一键安装
```bash
bash <(curl -sL https://raw.githubusercontent.com/zhy668/sock5/refs/heads/master/http_install.sh)
```

### 手动安装
```bash
# 克隆仓库
git clone https://github.com/zhy668/sock5.git
cd sock5

# 运行脚本
chmod +x install.sh
./install.sh
```

## 📋 功能菜单

### SOCKS5 代理管理 (install.sh)
```
============================================
     SOCKS5 代理 (Dante) 管理脚本
============================================
当前服务状态:
  - SOCKS5 (Dante): ✅ 已安装并正在运行 (Active)
--------------------------------------------
请选择操作:
  1) 安装 SOCKS5 代理 (Dante)
  2) 卸载 SOCKS5 代理 (Dante)
  0) 退出脚本
```

### HTTP 代理管理 (http_install.sh)
```
============================================
     HTTP/HTTPS 代理 (Squid) 管理脚本
============================================
当前服务状态:
  - HTTP (Squid): ✅ 已安装并正在运行 (Active)
--------------------------------------------
请选择操作:
  1) 安装 HTTP 代理 (Squid)
  2) 卸载 HTTP 代理 (Squid)
  0) 退出脚本
```

## 🔧 技术特点

### HTTP 代理 (Squid)
- **系统包安装**: 使用系统包管理器安装，稳定可靠
- **htpasswd 认证**: 使用 Apache htpasswd 进行用户认证
- **高性能**: 成熟的代理服务器，支持缓存和高并发
- **端口配置**: 默认端口 8888，避免与其他服务冲突
- **访问控制**: 精细的访问控制规则配置

### SOCKS5 代理 (Dante)
- **系统用户认证**: 使用 VPS 系统用户进行认证
- **PAM 支持**: 完整的 PAM 认证模块配置
- **高兼容性**: 支持各种 SOCKS5 客户端
- **端口配置**: 默认端口 8087

## � 系统支持

脚本支持主流 Linux 发行版：

| 系统 | 版本 | 支持状态 |
|------|------|----------|
| Ubuntu | 18.04+ | ✅ 完全支持 |
| Debian | 9+ | ✅ 完全支持 |
| CentOS | 7+ | ✅ 完全支持 |
| RHEL | 7+ | ✅ 完全支持 |

## 📊 状态显示

脚本会显示详细的代理状态信息：

```
============================================
代理服务器状态总览
============================================
服务器IP: xxx.xxx.xxx.xxx

--------------------------------------------
SOCKS5 (Dante) 代理状态:
  状态: ✅ 已安装并正在运行 (Active)
  连接信息:
    - 服务器: xxx.xxx.xxx.xxx
    - 端口: 8087
    - 协议: SOCKS5
    - 认证: 系统用户认证 (如: root用户)

--------------------------------------------
HTTP (Squid) 代理状态:
  状态: ✅ 已安装并正在运行 (Active)
  连接信息:
    - 服务器: xxx.xxx.xxx.xxx
    - 端口: 8888
    - 协议: HTTP/HTTPS
    - 认证: htpasswd认证
    - 用户名: your_username
============================================
```

## 🛠️ 系统要求

- **操作系统**: Ubuntu/Debian/CentOS/RHEL
- **权限**: Root 权限
- **网络**: 能够访问软件源和下载依赖包
- **端口**: 确保目标端口（8087, 8888）未被占用

## � 使用示例

### HTTP 代理连接示例
```bash
# 使用 curl 测试 HTTP 代理
curl -x http://username:password@your_server_ip:8888 http://httpbin.org/ip

# 浏览器代理设置
# HTTP 代理: your_server_ip:8888
# 用户名: your_username
# 密码: your_password
```

### SOCKS5 代理连接示例
```bash
# 使用 curl 测试 SOCKS5 代理
curl --socks5 username:password@your_server_ip:8087 http://httpbin.org/ip

# 浏览器代理设置
# SOCKS5 代理: your_server_ip:8087
# 用户名: 系统用户名 (如 root)
# 密码: 系统用户密码
```

## 📝 更新日志

### v3.0.0 (最新)
- ✨ HTTP 代理切换到 Squid，更稳定可靠
- 🚀 独立的 HTTP 代理管理脚本 (http_install.sh)
- 🔧 优化端口配置：HTTP 8888，SOCKS5 8087
- 📊 改进认证系统：HTTP 使用 htpasswd，SOCKS5 使用系统用户
- 🛡️ 增强访问控制和安全配置

### v2.0.0
- ✨ 新增预编译二进制文件支持
- 🚀 大幅提升安装速度
- 🔧 优化系统架构检测
- 📊 改进状态显示界面

### v1.0.0
- 🎉 初始版本发布
- 支持 HTTP 和 SOCKS5 代理管理
- 统一的菜单界面
- 完整的安装和卸载功能

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## 📄 许可证

MIT License
