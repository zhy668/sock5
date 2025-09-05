# 🚀 HTTP & SOCKS5 代理一键管理工具

一个功能全面、界面美观的代理服务器管理脚本，支持 HTTP (Squid) 和 SOCKS5 (Dante) 代理的一键安装、配置和管理。

## ✨ 核心特性

- 🔧 **双协议支持**: 同时支持 HTTP (Squid) 和 SOCKS5 (Dante) 代理
- 🛡️ **独立认证**: HTTP 使用 htpasswd 认证，SOCKS5 使用系统用户认证
- 📊 **智能监控**: 实时显示代理服务状态和连接信息，支持详细状态检查
- 🔥 **自动配置**: 自动配置防火墙、服务管理等
- 🌐 **多系统支持**: 支持 Ubuntu/Debian/CentOS 系统
- ⚡ **性能优化**: IP缓存机制、重试机制、超时控制
- 🔍 **详细诊断**: 提供详细的错误诊断和日志查看建议
- 🔐 **密码管理**: 支持覆盖已存在用户密码

## 🚀 快速开始

### 一键安装（支持SOCKS5和HTTP代理）
```bash
bash <(curl -sL https://raw.githubusercontent.com/zhy668/sock5/refs/heads/master/install.sh)
```

### 手动安装
```bash
# 克隆仓库
git clone https://github.com/zhy668/sock5.git
cd sock5

# 运行脚本
chmod +x install.sh
./install.sh


## 🔧 技术特点

### HTTP 代理 (Squid)
- **系统包安装**: 使用系统包管理器安装，稳定可靠
- **htpasswd 认证**: 使用 Apache htpasswd 进行用户认证
- **高性能**: 成熟的代理服务器，支持缓存和高并发
- **端口配置**: 默认端口 8888，避免与其他服务冲突
- **密码显示**: 安装后明文显示密码，方便使用

### SOCKS5 代理 (Dante)
- **系统用户认证**: 使用 VPS 系统用户进行认证
- **PAM 支持**: 完整的 PAM 认证模块配置
- **高兼容性**: 支持各种 SOCKS5 客户端
- **端口配置**: 默认端口 8087

## � 系统支持



| 系统 | 版本 | 支持状态 |
|------|------|----------|
| Ubuntu | 18.04+ | ✅ 完全支持 |
| Debian | 9+ | ✅ 完全支持 |
| CentOS | 7+ | ✅ 完全支持 |
| RHEL | 7+ | ✅ 完全支持 |

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

```

### SOCKS5 代理连接示例
```bash
# 使用 curl 测试 SOCKS5 代理
curl --socks5 username:password@your_server_ip:8087 http://httpbin.org/ip
```

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## 📄 许可证

MIT License
