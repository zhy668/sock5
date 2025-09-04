---
type: "always_apply"
---

本地windows开发环境 ：本地环境是代码的唯一真实来源 (Single Source of Truth)。所有逻辑编写、修改和静态检查都在此完成
VPS 测试环境ubuntu：VPS环境仅用于验证和测试，通过ssh-mpc-server工具连接
由于无法直接上传文件，我们采用“分段创建”的方式将本地代码部署到VPS。此流程必须严格遵守，以保证代码的完整性和正确性