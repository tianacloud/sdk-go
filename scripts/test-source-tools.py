#!/usr/bin/env python3
"""Behavior checks for current-source export and encoded-hostname rejection."""
import base64
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent


class SourceToolsTest(unittest.TestCase):
    def setUp(self):
        (ROOT / '.artifacts').mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / '.artifacts')
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)

    def scan(self):
        return subprocess.run([sys.executable, str(ROOT / 'scripts/check-public-source.py'),
                               str(self.root)], capture_output=True)

    def test_rejects_plain_and_encoded_hosts_without_echoing_them(self):
        host = b'gateway.' + b'internal' + b'.example'
        target = self.root / 'candidate.txt'
        for content in (host, b'-----BEGIN CERTIFICATE-----\n' + base64.b64encode(host)
                        + b'\n-----END CERTIFICATE-----\n'):
            target.write_bytes(content)
            result = self.scan()
            self.assertEqual(result.returncode, 1)
            self.assertIn(b'candidate.txt', result.stdout)
            self.assertNotIn(host, result.stdout + result.stderr)
        target.write_text('ep-01j5c9m7q2v8x4k6n3r0t1w2yz.db.example.test')
        self.assertEqual(self.scan().returncode, 0)

    def test_rejects_bare_internal_domain(self):
        target = self.root / 'candidate.txt'
        target.write_bytes(b'internal' + b'.example')
        self.assertEqual(self.scan().returncode, 1)

    def test_exports_current_source_without_history_or_artifacts(self):
        source = self.root / 'source'
        (source / 'scripts').mkdir(parents=True)
        shutil.copy2(ROOT / 'scripts/export-source.py', source / 'scripts/export-source.py')
        (source / 'pending.go').write_text('package pending\n')
        (source / '.git').mkdir()
        (source / '.git/config').write_text('private history marker')
        (source / '.artifacts').mkdir()
        (source / '.artifacts/build').write_text('local build marker')
        destination = self.root / 'export'
        result = subprocess.run([sys.executable, str(source / 'scripts/export-source.py'),
                                 str(destination)], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((destination / 'pending.go').read_text(), 'package pending\n')
        self.assertFalse((destination / '.git').exists())
        self.assertFalse((destination / '.artifacts').exists())
        again = subprocess.run([sys.executable, str(source / 'scripts/export-source.py'),
                                str(destination)], capture_output=True)
        self.assertNotEqual(again.returncode, 0)

    def test_git_export_uses_modified_deleted_and_untracked_state(self):
        source = self.root / 'git-source'
        (source / 'scripts').mkdir(parents=True)
        shutil.copy2(ROOT / 'scripts/export-source.py', source / 'scripts/export-source.py')
        subprocess.run(['git', 'init', '--quiet', '--template=', '-b', 'snapshot-test', str(source)],
                       check=True, capture_output=True)
        (source / 'tracked.txt').write_text('baseline')
        (source / 'deleted.txt').write_text('remove from snapshot')
        subprocess.run(['git', '-C', str(source), 'add', 'tracked.txt', 'deleted.txt'],
                       check=True, capture_output=True)
        (source / 'tracked.txt').write_text('pending edit')
        (source / 'deleted.txt').unlink()
        (source / 'untracked.txt').write_text('new source')
        (source / '.gitignore').write_text('ignored.txt\n')
        (source / 'ignored.txt').write_text('local artifact')
        destination = self.root / 'git-export'
        result = subprocess.run([sys.executable, str(source / 'scripts/export-source.py'),
                                 str(destination)], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((destination / 'tracked.txt').read_text(), 'pending edit')
        self.assertEqual((destination / 'untracked.txt').read_text(), 'new source')
        self.assertFalse((destination / 'deleted.txt').exists())
        self.assertFalse((destination / 'ignored.txt').exists())
        self.assertFalse((destination / '.git').exists())


if __name__ == '__main__':
    unittest.main()
