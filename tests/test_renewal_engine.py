import importlib.util
import pathlib
import signal
import sys
import types
import unittest
from unittest.mock import patch

# Permit deterministic, mocked tests on Windows; actual worker only runs on Linux.
if sys.platform == 'win32':
    sys.modules['fcntl'] = types.SimpleNamespace(flock=lambda *args: None, LOCK_EX=2, LOCK_NB=4)
    signal.SIGKILL = 9
spec = importlib.util.spec_from_file_location('renewal_engine', pathlib.Path(__file__).resolve().parents[1] / 'renewal_engine.py')
engine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(engine)


class Process:
    pid = 1000
    def __init__(self, code=0): self.code = code
    def wait(self, timeout=None): return self.code


class RenewalTests(unittest.TestCase):
    def setUp(self):
        p = patch.multiple(engine, LOCK_PATH=str(pathlib.Path(__file__).resolve().parent / '.test.lock'))
        p.start(); self.addCleanup(p.stop)
        for obj, attr, value in [(engine.os, 'open', 42), (engine.os, 'close', None),
                                 (engine.fcntl, 'flock', None), (engine, '_trusted_executable', True)]:
            q = patch.object(obj, attr, return_value=value); q.start(); self.addCleanup(q.stop)
        q = patch.object(engine.os, 'fstat', return_value=types.SimpleNamespace(st_mode=0o100600, st_uid=0)); q.start(); self.addCleanup(q.stop)

    def test_match_new_leaf(self):
        with patch.object(engine, '_nginx_active', return_value=0), patch.object(engine, '_local', side_effect=['old', 'new']), \
             patch.object(engine, '_live', side_effect=[{'verified': True, 'sha256':'old'}, {'verified': True, 'sha256':'new'}]), \
             patch.object(engine.subprocess, 'Popen', return_value=Process()) as proc:
            r = engine.run('example.com', 'example.com')
        self.assertEqual(r['status'], 'verified')
        self.assertEqual(proc.call_args.args[0], ['/usr/bin/certbot','renew','--cert-name','example.com','--non-interactive'])
        self.assertNotIn('shell', proc.call_args.kwargs)

    def test_mismatch_not_success(self):
        with patch.object(engine, '_nginx_active', return_value=0), patch.object(engine, '_local', side_effect=['old','new']), \
             patch.object(engine, '_live', return_value={'verified':True,'sha256':'other'}), \
             patch.object(engine.subprocess, 'Popen', return_value=Process()):
            self.assertEqual(engine.run('example.com','example.com')['status'], 'unverified')

    def test_inactive_baseline_never_launches(self):
        with patch.object(engine, '_nginx_active', return_value=3), patch.object(engine.subprocess, 'Popen') as p:
            self.assertEqual(engine.run('example.com','example.com')['status'], 'failed')
            p.assert_not_called()

    def test_config_failure_does_not_start_nginx(self):
        with patch.object(engine, '_nginx_active', return_value=3), patch.object(engine, '_command', return_value=1) as cmd:
            self.assertIn('configuration test failed', engine._restore_nginx())
            cmd.assert_called_once_with([engine.NGINX, '-t'])

    def test_reject_flag_as_certificate_name(self):
        self.assertEqual(engine.run('example.com','--danger')['status'], 'failed')

    def test_no_change_is_not_claimed_renewal(self):
        with patch.object(engine, '_nginx_active', return_value=0), patch.object(engine, '_local', return_value='old'), \
             patch.object(engine, '_live', return_value={'verified': True, 'sha256':'old'}), \
             patch.object(engine.subprocess, 'Popen', return_value=Process()):
            self.assertEqual(engine.run('example.com','example.com')['status'], 'no_change')

    def test_timeout_group_exits_then_recovers(self):
        proc = Process()
        proc.wait = unittest.mock.Mock(side_effect=[engine.subprocess.TimeoutExpired('certbot', 600), -15])
        def killpg(pid, sig):
            if sig in (0, signal.SIGKILL): raise ProcessLookupError()
        with patch.object(engine, '_nginx_active', return_value=0), patch.object(engine, '_local', return_value='old'), \
             patch.object(engine, '_live', return_value={'verified': True, 'sha256':'old'}), \
             patch.object(engine.subprocess, 'Popen', return_value=proc), patch.object(engine.os, 'killpg', side_effect=killpg, create=True):
            r = engine.run('example.com','example.com')
        self.assertEqual(r['status'], 'timeout')
        self.assertEqual(r['nginx_recovery'], 'active')

    def test_timeout_group_alive_skips_recovery(self):
        proc = Process()
        proc.wait = unittest.mock.Mock(side_effect=[engine.subprocess.TimeoutExpired('certbot', 600), -15])
        with patch.object(engine, '_nginx_active', return_value=0), patch.object(engine, '_local', return_value='old'), \
             patch.object(engine, '_live', return_value={'verified': True, 'sha256':'old'}), \
             patch.object(engine.subprocess, 'Popen', return_value=proc), patch.object(engine.os, 'killpg', create=True), \
             patch.object(engine.time, 'monotonic', side_effect=[0, 4]), patch.object(engine, '_restore_nginx') as restore:
            r = engine.run('example.com','example.com')
        self.assertEqual(r['status'], 'timeout')
        restore.assert_not_called()

    def test_restoration_failure_blocks_success(self):
        with patch.object(engine, '_nginx_active', return_value=0), patch.object(engine, '_local', return_value='old'), \
             patch.object(engine, '_live', return_value={'verified': True, 'sha256':'old'}), \
             patch.object(engine.subprocess, 'Popen', return_value=Process()), \
             patch.object(engine, '_restore_nginx', return_value='start failed; manual intervention required'):
            self.assertEqual(engine.run('example.com','example.com')['status'], 'unverified')


if __name__ == '__main__': unittest.main()
