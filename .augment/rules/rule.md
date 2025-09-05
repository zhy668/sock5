---
type: "always_apply"
---

1，本地是windows开发环境 ：本地环境是代码的唯一真实来源 (Single Source of Truth)。所有逻辑编写、修改和静态检查都在此完成，本地测试的时候不用ssh-mpc-server工具
2，VPS 测试环境是ubuntu：VPS环境仅用于验证和测试，通过ssh-mpc-server工具连接
3，由于无法直接上传文件，我们采用上传到Gihub：https://github.com/zhy668/sock5.git，然后下载到vps测试
