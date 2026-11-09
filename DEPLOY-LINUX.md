# Linux 受控续期部署指南

此方案仅管理**本机已有的一个 Certbot 证书**。工作台和具有权限的续期服务分离：工作台不运行 Certbot，不控制系统调度配置，不能向 root 进程传入命令。生产部署前必须先在独立测试环境完整演练。以下命令由系统管理员执行；请将示例域名和证书名称替换为自己的值。

## 1. 检查现有自动化

- 已配置好 Certbot 证书和无人交互的验证方式，先用 `sudo certbot certificates` 确认准确证书名称。确保 Nginx 实际使用该证书，并且已有部署 hook 可让新证书加载。手工确认 Nginx 当前配置正常、回滚方案和服务健康检查可用。
- 检查 `systemctl list-timers --all` 和已有 cron，识别已有 Certbot 续期任务。管理员需要避免本工具与其他定时任务重复管理同一证书；不要盲目停用可能负责其他证书的现有任务。
- `certbot renew --dry-run --cert-name 证书名` 适合在受控测试环境中核对 ACME 配置，但可能运行已有钩子或影响服务，先检查钩子；它并不验证真实生产证书的部署是否生效。

## 2. 安装受信任执行代码

从经审查的项目目录执行，下面只复制固定的两个 Python 文件，不复制数据库或 Web 文件。`/opt`、`/etc`、`/var/lib` 的父目录及目标目录必须归 root 所有且不可被组或其他用户写入，也不能是符号链接。部署过程的源目录必须可信，不接受普通用户在复制过程中更改文件；升级时重复审查并由管理员安装。

```sh
sudo install -d -o root -g root -m 0755 /opt/certdesk /etc/certdesk /var/lib/certdesk
sudo install -o root -g root -m 0644 privileged_worker.py renewal_engine.py /opt/certdesk/
sudo install -o root -g root -m 0644 systemd/certdesk-renew.service /etc/systemd/system/
sudo install -o root -g root -m 0644 systemd/certdesk-renew.timer /etc/systemd/system/
```

请由 root 创建 `/etc/certdesk/managed.json`（属主 root、权限 `0600`），内容如下，仅支持这两个字段：

```json
{"domain":"www.example.com","cert_name":"example.com"}
```

例如用受控编辑器创建后执行 `sudo chown root:root /etc/certdesk/managed.json` 和 `sudo chmod 0600 /etc/certdesk/managed.json`。Web 页面上的检测域名与此文件互不相通；只有 root 修改该文件才能更改续期目标。请确认代码、配置及所有父目录的属主与权限，服务会拒绝不安全的路径。不要授予 Web 用户写入这些目录、文件、systemd 单元、Certbot 配置或部署钩子的权限。

## 3. 受控测试，再启用调度

```sh
sudo systemctl daemon-reload
sudo systemctl start certdesk-renew.service
sudo systemctl status certdesk-renew.service
sudo journalctl -u certdesk-renew.service -n 100 --no-pager
```

第一次启动就是**真实续期检查**，可能调用 Certbot 已有钩子并改动服务，并非演练；仅在确认已授权且维护窗口合适时执行。先在测试服务器验证证书未到期、成功续期、钩子失败、超时、Nginx 未运行和实际线上指纹不一致等情况。检查 `/var/lib/certdesk/status.json` 与 journal；摘要文件不含完整日志，日志可能包含环境信息，注意日志访问权限。

确认测试和现有调度策略后执行 `sudo systemctl enable --now certdesk-renew.timer`。该定时器每天计划运行两次，具有随机延迟和 `Persistent=true`；运行失败请检查 journal 和服务状态。`sudo systemctl disable --now certdesk-renew.timer` 可停用未来触发，但不会自动取消已经运行的任务。工作台关闭不影响系统定时器。勿将应用、源码或 Web 界面以 root 身份运行。

## 4. 工作台及限制

以普通、受限用户运行 `python3 server.py`，只在运行机器的 127.0.0.1 监听。远程使用可信 SSH 本地转发，不要暴露端口；启动时终端显示访问码，取得访问码或会话者可读写台账。本机端口访问本身不等于身份隔离，访问码不绑定系统用户，必须保护终端和会话。数据和页面显示不构成不可篡改审计。

系统服务的状态摘要由 root 原子写入 `/var/lib/certdesk/status.json`，工作台只读展示，不能由 Web 配置触发续期。状态表示最后一次执行结果，不是实时健康保障；需另行设置系统服务失败告警、证书到期告警、监控及定期恢复演练。本方案尚未在你的 Linux、Certbot、Nginx 和 CA 环境进行端到端验证。涉及密钥、DNS 凭据与部署钩子的授权仍由管理员管理。
