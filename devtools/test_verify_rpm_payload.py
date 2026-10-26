import stat
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import verify_rpm_payload as verifier
from verify_rpm_payload import payload_rows


class RpmPayloadTests(unittest.TestCase):
    def row(self, path='/opt/lintap/Lintap.dll', digest='a' * 64, flags=0, mode=stat.S_IFREG | 0o644):
        return f'{path}\t{digest}\t{flags}\t{mode:o}'

    def test_regular_payload_is_verified_config_is_not_read(self):
        rows = payload_rows(self.row() + '\n' + self.row('/etc/lintap/config.json', flags=1) + '\n' +
                            self.row('/opt/lintap', digest='', mode=stat.S_IFDIR | 0o755))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][1], 'a' * 64)

    def test_missing_digest_relative_path_or_no_payload_fail_closed(self):
        for text in (self.row(digest=''), self.row(path='relative'), self.row(flags=1)):
            with self.subTest(text=text), self.assertRaises(ValueError):
                payload_rows(text)

    def test_installed_payload_tamper_is_not_hidden_by_matching_package_name(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rpm = root / 'fixture.rpm'
            rpm.write_bytes(b'synthetic rpm transport')
            payload = []
            for name in ('Lintap.dll', 'WintapAPI.dll', 'network_ops_tracer.bpf.o', 'file_ops_tracer.bpf.o'):
                target = root / name
                target.write_bytes(name.encode())
                payload.append(self.row(str(target), hashlib.sha256(target.read_bytes()).hexdigest()))
            def query(*args):
                fmt = args[args.index('--qf') + 1]
                if fmt == '%{NAME}': return 'lintap'
                if fmt == '%{ARCH}:%{FILEDIGESTALGO}': return 'x86_64:8'
                if fmt.startswith('['): return '\n'.join(payload)
                return 'lintap-0.1.1-fixture.x86_64'
            with patch.object(verifier, 'rpm', side_effect=query), \
                 patch.object(verifier.platform, 'machine', return_value='x86_64'), \
                 patch.object(verifier.platform, 'freedesktop_os_release', return_value=dict(ID='rhel', VERSION_ID='9.6')), \
                 patch('sys.argv', ['verify', '--rpm', str(rpm), '--rpm-sha256', verifier.sha256(rpm)]), \
                 patch('builtins.print') as output:
                self.assertEqual(verifier.main(), 0)
                self.assertTrue(json.loads(output.call_args.args[0])['passed'])
                (root / 'Lintap.dll').write_bytes(b'different managed binary')
                self.assertEqual(verifier.main(), 1)
                self.assertFalse(json.loads(output.call_args.args[0])['passed'])
