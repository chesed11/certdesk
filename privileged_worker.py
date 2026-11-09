#!/usr/bin/python3
"""Fixed root-owned systemd entrypoint. Never accepts web input or CLI arguments."""
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from datetime import datetime, timezone

CODE_DIR = Path('/opt/certdesk')
CONFIG = Path('/etc/certdesk/managed.json')
STATUS_DIR = Path('/var/lib/certdesk')

def trusted(path, is_dir):
    """Reject symlinks, non-root ownership and writable path components."""
    path = Path(path)
    for current in (path, *path.parents):
        st = os.lstat(current)
        if stat.S_ISLNK(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise RuntimeError('不安全的属主、符号链接或写入权限: ' + str(current))
    st = os.lstat(path)
    if is_dir and not stat.S_ISDIR(st.st_mode):
        raise RuntimeError('需要目录: ' + str(path))
    if not is_dir and not stat.S_ISREG(st.st_mode):
        raise RuntimeError('需要普通文件: ' + str(path))

def load_config():
    trusted(CONFIG, False)
    if os.stat(CONFIG).st_size > 4096:
        raise ValueError('配置文件过大')
    with CONFIG.open('r', encoding='utf-8') as f:
        data = json.load(f)
    if not isinstance(data, dict) or set(data) != {'domain', 'cert_name'}:
        raise ValueError('配置必须包含且仅包含 domain 与 cert_name')
    domain, name = data['domain'], data['cert_name']
    if not isinstance(domain, str) or len(domain) > 253 or domain != domain.lower() or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', p) for p in domain.split('.')):
        raise ValueError('无效的 ASCII 域名')
    if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,252}', name):
        raise ValueError('无效的 Certbot 证书名称')
    return data

def write_status(status):
    trusted(STATUS_DIR, True)
    summaries = {'verified':'续期后线上证书验证通过', 'no_change':'未发现证书变化；请查看系统日志', 'unverified':'无法确认线上证书是否生效，请检查', 'failed':'执行失败，请检查系统日志', 'timeout':'执行超时，请检查 Nginx 及系统日志'}
    if status not in summaries:
        status = 'failed'
    data = {'status':status, 'summary':summaries[status], 'updated_at':datetime.now(timezone.utc).isoformat(timespec='seconds')}
    fd, path = tempfile.mkstemp(prefix='.status-', dir=STATUS_DIR)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False)
            f.flush()
            os.fchmod(f.fileno(), 0o644)
            os.fsync(f.fileno())
        os.replace(path, STATUS_DIR / 'status.json')
    finally:
        if os.path.exists(path): os.unlink(path)

def main():
    if len(sys.argv) != 1 or os.geteuid() != 0:
        raise RuntimeError('必须由系统管理员按固定方式运行，且不接受参数')
    trusted(CODE_DIR, True)
    trusted(CODE_DIR / 'privileged_worker.py', False)
    trusted(CODE_DIR / 'renewal_engine.py', False)
    config = load_config()
    sys.path.insert(0, str(CODE_DIR))
    import renewal_engine
    result = renewal_engine.run(config['domain'], config['cert_name'])
    print(json.dumps(result, ensure_ascii=False), flush=True)
    status = result.get('status', 'failed')
    write_status(status)
    return 0 if status in ('verified', 'no_change') else 1

if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as exc:
        print('执行失败: ' + str(exc), file=sys.stderr, flush=True)
        try: write_status('failed')
        except Exception as report_error: print('无法写入状态: ' + str(report_error), file=sys.stderr)
        sys.exit(1)
