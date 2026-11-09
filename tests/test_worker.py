import importlib.util
import json
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('privileged_worker', ROOT / 'privileged_worker.py')
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)

class WorkerTests(unittest.TestCase):
    def test_paths_reject_symlink_untrusted_owner_and_writable_ancestors(self):
        file_ok = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0)
        dir_ok = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
        candidate = Path('/opt/certdesk/privileged_worker.py')
        with patch.object(worker.os, 'lstat', side_effect=lambda p: file_ok if p == candidate else dir_ok):
            worker.trusted(candidate, False)
        for bad in (SimpleNamespace(st_mode=stat.S_IFDIR | 0o777, st_uid=0),
                    SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=1000),
                    SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0)):
            with patch.object(worker.os, 'lstat', side_effect=lambda p: file_ok if p == candidate else bad):
                with self.assertRaises(RuntimeError): worker.trusted(candidate, False)

    def test_policy_rejects_extra_fields_and_malformed_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / 'managed.json'
            with patch.object(worker, 'CONFIG', config), patch.object(worker, 'trusted'):
                for data in ({'domain':'example.com', 'cert_name':'--bad'},
                             {'domain':'example.com', 'cert_name':'ok', 'command':'id'}):
                    config.write_text(json.dumps(data), encoding='utf-8')
                    with self.assertRaises(ValueError): worker.load_config()
                config.write_text(json.dumps({'domain':'example.com','cert_name':'example.com'}), encoding='utf-8')
                self.assertEqual(worker.load_config()['cert_name'], 'example.com')

    def test_status_only_contains_sanitized_fixed_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            captured = {}
            def fake_replace(source, dest):
                captured.update(json.loads(Path(source).read_text(encoding='utf-8')))
                self.assertEqual(dest, Path(tmp) / 'status.json')
            with patch.object(worker, 'STATUS_DIR', Path(tmp)), patch.object(worker, 'trusted'), patch.object(worker.os, 'fchmod', create=True), patch.object(worker.os, 'replace', side_effect=fake_replace):
                worker.write_status('failed')
            result = captured
            self.assertEqual(set(result), {'status','summary','updated_at'})
            self.assertEqual(result['status'], 'failed')

    def test_systemd_never_executes_workspace_or_accepts_web_inputs(self):
        service = (ROOT / 'systemd' / 'certdesk-renew.service').read_text(encoding='utf-8')
        timer = (ROOT / 'systemd' / 'certdesk-renew.timer').read_text(encoding='utf-8')
        self.assertIn('ExecStart=/usr/bin/python3 -I /opt/certdesk/privileged_worker.py', service)
        self.assertIn('Persistent=true', timer)

if __name__ == '__main__':
    unittest.main()
