"""Unprivileged HTTPS inspection only; never runs a renewal."""
import re
import socket
import ssl

def check_tls(body):
    if not isinstance(body, dict) or set(body) != {'domain'} or not isinstance(body['domain'], str):
        raise ValueError('请提供域名')
    domain = body['domain'].strip().lower()
    if len(domain) > 253 or not domain or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part) for part in domain.split('.')):
        raise ValueError('请输入有效 ASCII 域名，不含端口或路径')
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as tls:
                peer = tls.getpeercert()
        return {'ok': True, 'message': '证书链和域名验证通过；仅代表本次连接的端点。', 'expires_at': peer.get('notAfter', '')}
    except (OSError, ssl.SSLError, ValueError) as exc:
        return {'ok': False, 'message': 'TLS 验证或连接失败：' + str(exc)[:400], 'expires_at': ''}
