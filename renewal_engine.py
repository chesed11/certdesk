"""Privileged, fixed-operation Certbot renewal runner for Linux.

Called only by privileged_worker using its root-owned policy. No shell or
web/database-controlled commands are accepted. Output never contains key data.
"""
import fcntl
import hashlib
import os
import re
import signal
import socket
import ssl
import stat
import subprocess
import time
from pathlib import Path

CERTBOT_PATHS = ('/usr/bin/certbot', '/usr/local/bin/certbot', '/snap/bin/certbot')
SYSTEMCTL = '/usr/bin/systemctl'
NGINX = '/usr/sbin/nginx'
LOCK_PATH = '/run/certdesk-renewal.lock'
CERT_DIR = Path('/etc/letsencrypt/live')
RENEW_TIMEOUT = 600
GRACE_SECONDS = 15


def _trusted_executable(path):
    """Reject root-run executables or ancestor directories writable by others."""
    try:
        for candidate in (Path(path), Path(os.path.realpath(path))):
            for part in (candidate, *candidate.parents):
                entry = part.lstat()
                if entry.st_uid != 0:
                    return False
                if not stat.S_ISLNK(entry.st_mode) and entry.st_mode & 0o022:
                    return False
        target = os.stat(path)
        return stat.S_ISREG(target.st_mode) and bool(target.st_mode & 0o111)
    except OSError:
        return False


def _command(args, timeout=15):
    try:
        p = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=timeout, check=False)
        return p.returncode
    except (OSError, subprocess.TimeoutExpired):
        return None


def _live(domain):
    """Require normal certificate-chain and hostname validation."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=8) as raw:
            with ctx.wrap_socket(raw, server_hostname=domain) as tls:
                der = tls.getpeercert(binary_form=True)
                return {'verified': True, 'sha256': hashlib.sha256(der).hexdigest()}
    except (OSError, ssl.SSLError, ValueError) as exc:
        return {'verified': False, 'error': str(exc)[:250]}


def _local(cert_name):
    # cert_name has no path separators; only the public certificate is read.
    try:
        pem = (CERT_DIR / cert_name / 'cert.pem').read_text(encoding='ascii')
        der = ssl.PEM_cert_to_DER_cert(pem)
        return hashlib.sha256(der).hexdigest()
    except (OSError, ValueError, UnicodeError):
        return None


def _nginx_active():
    return _command([SYSTEMCTL, 'is-active', '--quiet', 'nginx.service'])


def _restore_nginx():
    """Only called after a verified active baseline and the child is stopped."""
    state = _nginx_active()
    if state == 0:
        return 'active'
    if state != 3:
        return 'unknown; manual intervention required'
    if _command([NGINX, '-t']) != 0:
        return 'configuration test failed; not started; manual intervention required'
    if _command([SYSTEMCTL, 'start', 'nginx.service'], timeout=45) != 0:
        return 'start failed; manual intervention required'
    if _nginx_active() != 0:
        return 'start not confirmed; manual intervention required'
    return 'restored; verify application health manually'


def run(domain, cert_name):
    """Run one scoped renewal; return a JSON-serializable outcome.

    A validated trusted policy must supply the domain and exact Certbot name.
    An exit code of zero never alone proves a new certificate was deployed.
    """
    result = {'status': 'failed', 'summary': '', 'details': [], 'pre_tls': None,
              'post_tls': None, 'local_fingerprint': None, 'nginx_recovery': 'not attempted'}
    if (not isinstance(domain, str) or len(domain) > 253 or
            not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x)
                    for x in domain.split('.')) or
            not isinstance(cert_name, str) or
            not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,252}', cert_name)):
        result['summary'] = 'Invalid managed domain or certificate name.'
        return result
    lock = None
    try:
        flags = os.O_CREAT | os.O_RDWR | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NOFOLLOW', 0)
        lock = os.open(LOCK_PATH, flags, 0o600)
        info = os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise PermissionError('Untrusted lock file')
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            result['summary'] = 'Another renewal is already running.'
            return result
        program = next((p for p in CERTBOT_PATHS if _trusted_executable(p)), None)
        if not program:
            result['summary'] = 'Trusted Certbot not found at a supported fixed path.'
            return result
        if not _trusted_executable(SYSTEMCTL) or not _trusted_executable(NGINX):
            result['summary'] = 'Nginx or systemctl is not a trusted root-owned executable.'
            return result
        if _nginx_active() != 0:
            result['summary'] = 'Nginx was not confirmed active before renewal; no changes made.'
            return result
        before_local = _local(cert_name)
        if not before_local:
            result['summary'] = 'Cannot read the managed public certificate; no changes made.'
            return result
        result['pre_tls'] = _live(domain)
        try:
            proc = subprocess.Popen([program, 'renew', '--cert-name', cert_name, '--non-interactive'],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, start_new_session=True)
        except OSError as exc:
            result['summary'] = 'Certbot could not be started: ' + str(exc)[:200]
            return result
        timed_out = False
        try:
            code = proc.wait(timeout=RENEW_TIMEOUT)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                code = proc.wait(timeout=GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    code = proc.wait(timeout=GRACE_SECONDS)
                except subprocess.TimeoutExpired:
                    code = None
                    result['details'].append('Certbot process did not exit; manual intervention required.')
            # A hook may outlive the Certbot parent. Stop any remaining members
            # before recovery; never assume that wait() reaped the whole group.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + 3
            while True:
                try:
                    os.killpg(proc.pid, 0)
                except ProcessLookupError:
                    break
                if time.monotonic() >= deadline:
                    result['status'] = 'timeout'
                    result['summary'] = 'Timed out; process group not confirmed stopped. Manual recovery required.'
                    result['nginx_recovery'] = 'not attempted; process group still present'
                    return result
                time.sleep(.1)
        # Even a completed process can leave nginx stopped due to a hook failure.
        result['nginx_recovery'] = _restore_nginx()
        result['local_fingerprint'] = _local(cert_name)
        result['post_tls'] = _live(domain)
        if timed_out:
            result['status'] = 'timeout'
            result['summary'] = 'Certbot timed out; recovery attempted; inspect server and Certbot logs.'
        elif code != 0:
            result['summary'] = 'Certbot failed; inspect server and Certbot logs.'
            result['details'].append('Certbot exit code: ' + str(code))
        elif result['nginx_recovery'] not in ('active', 'restored; verify application health manually'):
            result['status'] = 'unverified'
            result['summary'] = 'Nginx recovery or health could not be confirmed.'
        elif not result['local_fingerprint'] or not result['post_tls']['verified']:
            result['status'] = 'unverified'
            result['summary'] = 'Certificate or validated HTTPS endpoint unavailable after renewal.'
        elif result['local_fingerprint'] != result['post_tls']['sha256']:
            result['status'] = 'unverified'
            result['summary'] = 'Online leaf certificate does not match the local Certbot certificate.'
        elif before_local == result['local_fingerprint']:
            result['status'] = 'no_change'
            result['summary'] = 'No local certificate change; online certificate matches. Certbot may not consider it due.'
        else:
            result['status'] = 'verified'
            result['summary'] = 'New local certificate matches the validated HTTPS endpoint.'
        result['details'].append('HTTPS check covers one resolved endpoint only.')
        return result
    except OSError as exc:
        result['summary'] = 'Lock or system error: ' + str(exc)[:200]
        return result
    finally:
        if lock is not None:
            os.close(lock)
