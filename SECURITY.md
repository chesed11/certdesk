# 安全政策

本项目处于实验阶段，尚未在真实 Linux、systemd、Certbot 和 Nginx 环境完成端到端验证；不要将其直接用于生产服务或作为唯一的证书到期监控。项目目前没有安全更新响应时限或长期支持承诺。

## 报告漏洞

如果仓库已启用 GitHub 私密漏洞报告，请在仓库的 **Security and quality → Advisories** 页面选择 **Report a vulnerability**，私下向维护者提交报告。此入口需要仓库管理员先行启用，并不会因添加本文件自动开启。[GitHub 使用说明](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/report-privately)

若看不到该入口，请联系维护者索取私密报告方式；也可以提交一条不包含漏洞细节的公开 issue，询问安全联系方式。请不要在公开 issue、讨论区或提交记录中发布漏洞细节、真实证书私钥、访问令牌或其他凭据。

报告中请在安全渠道提供受影响版本或提交、运行环境、影响说明以及可在隔离环境复现的步骤；对日志和配置进行脱敏。请给维护者合理的调查和修复时间，商议披露安排。

## 维护者发布前检查

创建公开仓库后，管理员应在 GitHub 仓库设置中启用私密漏洞报告，并确认自己能接收安全通知。详见 [GitHub 配置说明](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/configure-vulnerability-reporting/configure-for-a-repository)。
