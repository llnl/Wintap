#!/usr/bin/env python3
"""Unprivileged safety/format tests; never launches a collector or changes ownership."""
import json
import os
import pwd
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import lintap_cpu_investigation as investigation


class InvestigationTests(unittest.TestCase):
    def test_existing_collector_blocks_compare(self):
        with mock.patch.object(investigation, 'lintap_pids', return_value=[123]), \
                mock.patch.object(investigation, 'service_status') as service:
            with self.assertRaisesRegex(RuntimeError, 'stop them yourself'):
                investigation.require_idle()
            service.assert_not_called()

    def test_enabled_or_active_service_blocks_compare(self):
        for status in ({'enabled': 'enabled', 'active': 'inactive'},
                       {'enabled': 'disabled', 'active': 'active'}):
            with mock.patch.object(investigation, 'lintap_pids', return_value=[]), \
                    mock.patch.object(investigation, 'service_status', return_value=status):
                with self.assertRaisesRegex(RuntimeError, 'disabled/inactive'):
                    investigation.require_idle()

    def test_disabled_service_allows_compare(self):
        with mock.patch.object(investigation, 'lintap_pids', return_value=[]), \
                mock.patch.object(investigation, 'service_status',
                                  return_value={'enabled': 'disabled', 'active': 'inactive'}):
            investigation.require_idle()

    def test_missing_service_is_normalized_without_parsing_error_text(self):
        with mock.patch.object(investigation, 'run',
                               return_value=mock.Mock(returncode=0, stdout='not-found\n')) as command:
            self.assertEqual(investigation.service_status(),
                             {'enabled': 'not-found', 'active': 'inactive'})
            self.assertEqual(command.call_count, 1)

    def test_absent_service_allows_compare(self):
        with mock.patch.object(investigation, 'lintap_pids', return_value=[]), \
                mock.patch.object(investigation, 'service_status',
                                  return_value={'enabled': 'not-found', 'active': 'inactive'}):
            investigation.require_idle()

    def test_systemctl_failure_is_not_treated_as_absence(self):
        with mock.patch.object(investigation, 'run',
                               return_value=mock.Mock(returncode=1, stdout='Failed to connect to bus')), \
                mock.patch.object(investigation, 'lintap_pids', return_value=[]):
            with self.assertRaisesRegex(RuntimeError, 'disabled/inactive'):
                investigation.require_idle()

    def test_log_export_is_numeric_only(self):
        with tempfile.TemporaryDirectory(dir='/tmp/opencode') as directory:
            root = Path(directory)
            log = root / 'raw.log'
            log.write_text(
                '11/2/2026 4:15:33 PM [Info] DuckDB operation timing (last ~60s): '
                'resolver.sql_other calls=2 total_ms=3.0 avg_ms=1.500 max_ms=2.0 failures=0\n'
                '11/2/2026 4:15:33 PM [Info] fileserializer: serializer_flush '
                'accepted_total=22 dropped_total=0 query=SECRET_ID\n'
                'PRIVATE_TIMESTAMP [Info] fileserializer: accepted_total=23\n'
                '11/2/2026 4:15:33 PM [Info] DuckDB operation timing (last ~60s): '
                'private.secret calls=1 total_ms=1 avg_ms=1 max_ms=1 failures=0\n'
                'SQL SELECT SECRET_ID FROM secrets; command_line=PRIVATE_COMMAND\n')
            investigation.aggregate_log(log, root)
            exported = (root / 'duckdb-operations.csv').read_text() + (root / 'pipeline-counters.csv').read_text()
            self.assertNotIn('SECRET', exported)
            self.assertNotIn('PRIVATE', exported)
            self.assertNotIn('private.secret', exported)
            self.assertIn('resolver.sql_other,2,3.0,1.500,2.0,0', exported)
            self.assertIn('fileserializer,accepted_total,22', exported)

    def test_unresolved_kernel_warning_and_flat_summing(self):
        with tempfile.TemporaryDirectory(dir='/tmp/opencode') as directory:
            root = Path(directory)
            def fake_report(command, stdout, stderr):
                if '--no-children' in command:
                    stdout.write(' 44.24% [kernel.kallsyms] [k] osq_lock\n'
                                 ' 10.00% [kernel.kallsyms] [k] 0xffffffff12345678\n'
                                 ' 20.00% libduckdb.so [.] duckdb::RandomEngine::RandomEngine\n')
                return mock.Mock(returncode=0)
            with mock.patch.object(investigation.subprocess, 'run', side_effect=fake_report):
                investigation.reports(root / 'perf.data', root / 'reports')
            summary = json.loads((root / 'reports/profile-summary.json').read_text())
            self.assertEqual(summary['kernel_self_percent_rounded'], 54.24)
            self.assertEqual(summary['unresolved_kernel_self_percent_rounded'], 10)
            self.assertEqual(summary['duckdb_self_percent_rounded'], 20)
            self.assertEqual(len(summary['rng_lock_symbols']), 2)

    def test_detailed_profiles_stay_local_and_summary_uses_fixed_labels(self):
        with tempfile.TemporaryDirectory(dir='/tmp/opencode') as directory:
            root = Path(directory)
            def fake_report(command, stdout, stderr):
                stdout.write(' 10.00% /private/libduckdb.so [.] duckdb::RandomEngine /private/source\n')
                stderr.write('warning: /private/capture\n')
                return mock.Mock(returncode=0)
            with mock.patch.object(investigation.subprocess, 'run', side_effect=fake_report):
                investigation.reports(root / 'perf.data', root / 'local', root / 'shared')
            self.assertEqual([p.name for p in (root / 'shared').iterdir()], ['profile-summary.json'])
            exported = (root / 'shared/profile-summary.json').read_text()
            self.assertNotIn('/private', exported)
            self.assertIn('RandomEngine', exported)
            self.assertEqual(json.loads(exported)['perf_report_warning_count'], 2)

    def test_inventory_omits_identity_paths_and_non_numeric_config(self):
        with tempfile.TemporaryDirectory(dir='/tmp/opencode') as directory:
            root = Path(directory)
            dll = root / 'Lintap.dll'
            dll.write_bytes(b'test')
            (root / 'ETLConfig.json').write_text(json.dumps({'DisableMCP': True,
                'SkipEsperSend': '/private/config', 'Adapters': []}))
            with mock.patch.object(investigation, 'text', return_value=''), \
                    mock.patch.object(investigation, 'service_status', return_value={'enabled': 'disabled', 'active': 'inactive'}), \
                    mock.patch.object(investigation, 'lintap_pids', return_value=[123]), \
                    mock.patch.object(investigation, 'run', return_value=mock.Mock(returncode=0, stdout='/private/runtime')), \
                    mock.patch.object(Path, 'read_bytes', return_value=b'WINTAP_DUCKDB_RESOLVER_THREADS=/private/secret'):
                investigation.inventory(root, str(dll), str(dll), pid=123, runtime_root=str(root))
            exported = (root / 'inventory.json').read_text()
            self.assertNotIn('/private', exported)
            data = json.loads(exported)
            for key in ('host', 'boot_id', 'lintap_pids', 'cgroup'):
                self.assertNotIn(key, data)
            self.assertEqual(data['config_flags'], {'DisableMCP': True})
            self.assertEqual(data['collector_environment']['WINTAP_DUCKDB_RESOLVER_THREADS'], '<redacted>')

    def test_git_worktree_outputs_are_rejected_including_symlinks(self):
        with tempfile.TemporaryDirectory(dir='/tmp/opencode') as directory:
            root = Path(directory)
            repo = root / 'repo'
            repo.mkdir()
            (repo / '.git').write_text('gitdir: external\n')
            (root / 'link').symlink_to(repo, target_is_directory=True)
            for path in (repo / 'new/output', root / 'link/output'):
                with self.assertRaisesRegex(RuntimeError, 'outside Git'):
                    investigation.require_outside_git(path)
            investigation.require_outside_git(root / 'private')

    def test_proc_sampling_excludes_children(self):
        fields = ['0'] * 22
        fields[11], fields[12] = '100', '50'
        fields[13], fields[14] = '9999', '9999'
        fields[17], fields[21] = '7', '3'
        with mock.patch.object(Path, 'read_text', return_value='42 (name with ) brackets) ' + ' '.join(fields)), \
                mock.patch.object(investigation.os, 'sysconf', return_value=4096):
            sample = investigation.proc_sample(42)
        self.assertEqual(sample, {'cpu_ticks': 150, 'threads': 7, 'rss_bytes': 12288})

    def test_publish_streams_local_reports_without_opening_permissions(self):
        # Execute real tar/pipe operations without privilege switching or chown.
        # Check the privilege split separately through the recorded commands.
        actual_run = subprocess.run
        commands = []
        def unprivileged_run(command, **kwargs):
            commands.append(command)
            if command[0] == 'runuser':
                command = command[4:]
            if command[0] == 'chown':
                return mock.Mock(returncode=0)
            return actual_run(command, **kwargs)
        with tempfile.TemporaryDirectory(dir='/tmp/opencode') as directory:
            root = Path(directory)
            local = root / 'private-local'
            result = local / 'results'
            result.mkdir(parents=True, mode=0o700)
            os.chmod(str(local), 0o700)
            (result / 'inventory.json').write_text('{"fips":1}\n')
            (local / 'raw-sensitive.log').write_text('NOT_FOR_PUBLICATION')
            owner = pwd.getpwuid(os.getuid()).pw_name
            with mock.patch.object(investigation.subprocess, 'run', side_effect=unprivileged_run):
                investigation.publish(result, local, root / 'shared', owner)
            published = root / 'shared' / local.name
            self.assertEqual((published / 'inventory.json').read_text(), '{"fips":1}\n')
            self.assertFalse((published / 'raw-sensitive.log').exists())
            self.assertEqual(local.stat().st_mode & 0o777, 0o700)
            extraction = next(c for c in commands if c[0] == 'runuser' and c[4] == 'tar')
            self.assertNotIn(str(result), extraction)
            self.assertIn('--no-same-owner', extraction)


if __name__ == '__main__':
    unittest.main()
