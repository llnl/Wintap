#!/usr/bin/env python3
"""Root-only, opt-in Lintap CPU investigation; Python 3.6+, standard library only."""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time


CONFIG_KEYS = ('DisableMCP', 'DisableDuckDBUI', 'DisableETL', 'DisableSensors',
               'DisableSettings', 'EnableDirectParquet', 'Execve', 'Clone', 'Exit',
               'Network', 'FileOps', 'SELinux', 'ProcessRundown', 'WriteToParquet',
               'SerializationIntervalSec', 'FileSerializationIntervalSec',
               'UploadIntervalSec', 'SkipProcessResolve', 'SkipParentProcessResolve',
                'SkipProcessRegister', 'SkipEsperSend')
OPERATIONS = {'etl.raw_sensor_copy'} | {'resolver.' + name for name in (
    'attributed_path', 'resolve_at_time', 'registry_teardown', 'process_exists',
    'register_process', 'upsert_process_start', 'get_pid_hash', 'get_all_processes',
    'db_lock_wait', 'db_lock_hold', 'sql_resolve_at_time', 'sql_register_process',
    'sql_get_pid_hash', 'sql_other')}


def run(command, **kwargs):
    return subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          universal_newlines=True, **kwargs)


def text(path):
    try:
        return Path(path).read_text(errors='replace')
    except OSError:
        return ''


def sha256(path):
    h = hashlib.sha256()
    with open(str(path), 'rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def lintap_pids():
    found = []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            args = (entry / 'cmdline').read_bytes().split(b'\0')
            if any(Path(os.fsdecode(arg)).name in ('Lintap', 'Lintap.dll') for arg in args if arg):
                found.append(int(entry.name))
        except OSError:
            pass
    return sorted(found)


def service_status():
    # is-enabled prints different error text for missing units across systemd
    # versions. Use LoadState rather than treating human-readable stderr as state.
    loaded = run(['systemctl', 'show', 'lintap-pidstat.service', '--property=LoadState', '--value'])
    if loaded.returncode == 0 and loaded.stdout.strip() == 'not-found':
        return {'enabled': 'not-found', 'active': 'inactive'}
    return {key: run(['systemctl', action, 'lintap-pidstat.service']).stdout.strip()
            for key, action in (('enabled', 'is-enabled'), ('active', 'is-active'))}


def require_idle():
    pids = lintap_pids()
    if pids:
        raise RuntimeError('Existing Lintap PID(s) {}: stop them yourself before compare.'.format(pids))
    service = service_status()
    if service['enabled'] not in ('disabled', 'not-found') or service['active'] not in ('inactive', 'unknown'):
        raise RuntimeError('lintap-pidstat.service must remain disabled/inactive: {}'.format(service))


def inventory(destination, dll, dotnet, pid=None, runtime_root='/var/log/lintap/runtime'):
    data = {
        'kernel': os.uname().release, 'fips_enabled': text('/proc/sys/crypto/fips_enabled').strip(),
        'perf_event_paranoid': text('/proc/sys/kernel/perf_event_paranoid').strip(),
        'kptr_restrict': text('/proc/sys/kernel/kptr_restrict').strip(),
        'loadavg': text('/proc/loadavg').split()[:3],
        'pidstat_service_safe': service_status() in (
            {'enabled': 'disabled', 'active': 'inactive'},
            {'enabled': 'not-found', 'active': 'inactive'}),
        'collector_count': len(lintap_pids()),
        'runner_cpu_affinity': sorted(os.sched_getaffinity(0)),
        'logical_cpu_count': os.cpu_count(),
        'versions': {}, 'hashes': {}, 'config_flags': {},
    }
    commands = {
        'crypto_policy': ['update-crypto-policies', '--show'],
    }
    for name, path in (('dotnet_filesystem', dotnet), ('runtime_filesystem', runtime_root)):
        if Path(path).exists():
            commands[name] = ['findmnt', '-T', str(path), '-n', '-o', 'FSTYPE']
    data['event_store_file_metadata'] = {}
    for leaf in ('main.pid-v2.duckdb', 'main.pid-v2.duckdb.wal'):
        candidate = Path(runtime_root) / 'event_store' / leaf
        if candidate.is_file():
            stat = candidate.stat()
            data['event_store_file_metadata'][leaf] = {'bytes': stat.st_size}
    if Path(dotnet).is_file():
        commands['dotnet'] = [dotnet, '--version']
    for name, command in commands.items():
        if shutil.which(command[0]):
            response = run(command, timeout=30)
            value = response.stdout.strip()
            if response.returncode == 0 and re.fullmatch(r'[A-Za-z0-9_.:+-]{1,80}', value):
                data['versions'][name] = value
    # Record quota/cpuset files from this runner's inherited cgroups (the canary inherits them).
    quotas = {}
    for line in text('/proc/self/cgroup').splitlines():
        parts = line.split(':', 2)
        if len(parts) != 3:
            continue
        _, controllers, relative = parts
        for controller in controllers.split(',') if controllers else ['']:
            mount = Path('/sys/fs/cgroup') / controller
            root = mount / relative.lstrip('/')
            while root == mount or mount in root.parents:
                for leaf in ('cpu.max', 'cpu.cfs_quota_us', 'cpu.cfs_period_us',
                             'cpuset.cpus', 'cpuset.cpus.effective'):
                    value = text(root / leaf).strip()
                    if value and re.fullmatch(r'[0-9, -]+|max \d+', value):
                        quotas.setdefault(leaf, []).append(value)
                if root == mount:
                    break
                root = root.parent
    data['cgroup_limits'] = quotas
    if pid:
        for line in text('/proc/{}/status'.format(pid)).splitlines():
            if line.split(':')[0] in ('Threads', 'VmRSS', 'Cpus_allowed_list', 'Mems_allowed_list'):
                data.setdefault('collector_status', []).append(line)
        # Never dump a complete environment (it can contain credentials).
        try:
            allowed = ['WINTAP_DUCKDB_RESOLVER_THREADS', 'WINTAP_DUCKDB_DIAGNOSTICS',
                       'DOTNET_PerfMapEnabled', 'COMPlus_PerfMapEnabled']
            env = Path('/proc/{}/environ'.format(pid)).read_bytes().split(b'\0')
            data['collector_environment'] = {}
            for key in allowed:
                value = next((os.fsdecode(v).split('=', 1)[1] for v in env
                              if v.startswith((key + '=').encode())), '<unset>')
                data['collector_environment'][key] = value if re.fullmatch(r'\d{1,10}|<unset>', value) else '<redacted>'
        except OSError:
            data['collector_environment'] = 'unavailable'
    dll_path = Path(dll)
    for candidate in (dll_path, dll_path.parent / 'libduckdb.so', Path(dotnet)):
        if candidate.is_file():
            data['hashes'][candidate.name] = sha256(candidate)
    for candidate in dll_path.parent.glob('runtimes/**/libduckdb.so'):
        data['hashes'][str(candidate.relative_to(dll_path.parent))] = sha256(candidate)
    config_path = dll_path.parent / 'ETLConfig.json'
    if config_path.is_file():
        config = json.loads(config_path.read_text())
        data['config_flags'] = {key: config[key] for key in CONFIG_KEYS
                                if key in config and isinstance(config[key], (bool, int, float))}
        data['enabled_adapter_count'] = sum(bool(a.get('Enabled')) for a in config.get('Adapters', []))
    (destination / 'inventory.json').write_text(json.dumps(data, indent=2) + '\n')


def reports(perf_file, destination, summary_destination=None):
    # Detailed perf output can contain source paths, thread names, and addresses.
    # Keep it private; publish only fixed-label numeric aggregates.
    destination.mkdir(parents=True, exist_ok=True)
    for name, options in (
            ('self-time.txt', ['--no-children', '--call-graph', 'none', '--percent-limit', '0', '--sort', 'dso,symbol']),
            ('call-chains.txt', ['--call-graph', '--percent-limit', '0.5', '--sort', 'comm,dso,symbol'])):
        with open(str(destination / name), 'w') as out, open(str(destination / (name + '.stderr')), 'w') as err:
            result = subprocess.run(['perf', 'report', '--input', str(perf_file), '--stdio'] + options,
                                    stdout=out, stderr=err)
        if result.returncode:
            raise RuntimeError('perf report failed: {}'.format(destination / (name + '.stderr')))
    # Summarize self time across all thread names; do not sum overlapping call chains.
    rows = []
    for line in text(destination / 'self-time.txt').splitlines():
        match = re.match(r'\s*([\d.]+)%\s+(\S+)\s+\[([.k])\]\s+(.*)', line)
        if match:
            value, dso, kind, symbol = match.groups()
            rows.append((float(value), dso, kind, symbol.split('  ')[0].strip()))
    summary = {
        'kernel_self_percent_rounded': round(sum(v for v, d, k, s in rows if k == 'k'), 2),
        'duckdb_self_percent_rounded': round(sum(v for v, d, k, s in rows if 'duckdb' in d), 2),
        'unresolved_kernel_self_percent_rounded': round(sum(v for v, d, k, s in rows if k == 'k' and s.startswith('0x')), 2),
        'rng_lock_symbols': [{'percent': round(sum(v for v, d, k, s in rows
                                                  if re.search(label, s, re.I)), 2), 'symbol': label}
                             for label in ('osq_lock', 'getrandom', 'drbg', 'RandomEngine')
                             if any(re.search(label, s, re.I) for v, d, k, s in rows)],
        'perf_report_warning_count': sum(len(text(destination / (name + '.stderr')).splitlines())
                                         for name in ('self-time.txt', 'call-chains.txt')),
        'perf_record_loss_warning_count': sum('lost' in line.lower() for line in
                                              text(perf_file.parent / 'perf-record.log').splitlines()),
        'warning': 'No named RNG hotspot is NOT evidence of absence if kernel symbols remain unresolved. '
                   'Old captures may need matching kernel/build-ID symbols; this script changes no sysctls.',
    }
    (summary_destination or destination).mkdir(parents=True, exist_ok=True)
    ((summary_destination or destination) / 'profile-summary.json').write_text(json.dumps(summary, indent=2) + '\n')


def proc_sample(pid):
    fields = Path('/proc/{}/stat'.format(pid)).read_text().rsplit(')', 1)[1].split()
    # Fields after comm start at stat field 3; count this process, not child processes.
    return {'cpu_ticks': int(fields[11]) + int(fields[12]), 'threads': int(fields[17]),
            'rss_bytes': int(fields[21]) * os.sysconf('SC_PAGE_SIZE')}


def aggregate_log(log, destination):
    rows = []
    counters = []
    for line in text(log).splitlines():
        timestamp = line.split(' [', 1)[0]
        if not re.fullmatch(r'\d{1,2}/\d{1,2}/\d{4} \d{1,2}:\d{2}:\d{2}(?: [AP]M)?', timestamp):
            continue
        category = 'unspecified'
        for known in ('fileserializer', 'processserializer', 'processstopserializer',
                      'tcpconnectionserializer', 'udppacketserializer', 'selinuxserializer',
                      'registryserializer', 'defaultserializer'):
            if known + ':' in line.lower():
                category = known
                break
        if 'DuckDB operation timing (last ~60s): ' in line:
            payload = line.split('DuckDB operation timing (last ~60s): ', 1)[1]
            for match in re.finditer(r'([a-z_.]+) calls=(\d+) total_ms=([\d.]+) avg_ms=([\d.]+) max_ms=([\d.]+) failures=(\d+)', payload):
                if match.group(1) in OPERATIONS:
                    rows.append([timestamp] + list(match.groups()))
        # Export only approved numeric aggregate keys, never raw log lines/identifiers.
        for match in re.finditer(r'\b(drained|remaining|elapsed_ms|skipped_overlap|parquet_backlog|accepted_total|dropped_total|peak_depth)=(\d+)', line):
            counters.append([timestamp, category] + list(match.groups()))
        match = re.search(r'Total Lintap messages received: (\d+)', line)
        if match:
            counters.append([timestamp, 'all', 'total_messages', match.group(1)])
    for name, header, values in (
            ('duckdb-operations.csv', ['local_time', 'operation', 'calls', 'total_ms', 'avg_ms', 'max_ms', 'failures'], rows),
            ('pipeline-counters.csv', ['local_time', 'category', 'metric', 'value'], counters)):
        with open(str(destination / name), 'w', newline='') as stream:
            writer = csv.writer(stream)
            writer.writerow(header)
            writer.writerows(values)


def stop_owned(process):
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            # Only this script's newly created canary process group, never an existing collector.
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)


def compare(args, local, result):
    require_idle()
    missing = ['--{} {}'.format(name, value) for name, value in (('dll', args.dll), ('dotnet', args.dotnet))
               if not Path(value).is_file()]
    if missing:
        raise RuntimeError('Missing file(s): {}. Supply paths to the complete canary bundle and dotnet executable.'.format(
            ', '.join(missing)))
    if not os.access(args.dotnet, os.X_OK):
        raise RuntimeError('dotnet is not executable: {}'.format(args.dotnet))
    if shutil.disk_usage(str(local)).free < 5 * 1024 ** 3:
        raise RuntimeError('Need at least 5 GiB free on local capture disk.')
    app = local / 'app'
    shutil.copytree(str(Path(args.dll).resolve().parent), str(app))
    config_path = app / 'ETLConfig.json'
    config = json.loads(config_path.read_text())
    config['Adapters'] = []  # Stronger than trusting inherited environment or remote credentials.
    for key in ('DataRootPath', 'DataRoot', 'RuntimeRoot'):
        config.pop(key, None)
    config_path.write_text(json.dumps(config, indent=2) + '\n')
    (result / 'test-plan.json').write_text(json.dumps({
        'legs': ['default-a', 'one-thread', 'default-b'], 'warmup_seconds': args.warmup,
        'measurement_seconds': args.duration, 'frequency_hz': args.frequency,
        'state': 'fresh event store in every leg; ambient workload, no generated stimulus',
        'adapters': [], 'dll_sha256': sha256(app / 'Lintap.dll'),
        'note': 'Fresh state cannot by itself explain the original accumulated-state failure.',
    }, indent=2) + '\n')
    for leg, limit in (('default-a', None), ('one-thread', '1'), ('default-b', None)):
        require_idle()
        print('Starting {} ({}s warmup, {}s capture)'.format(leg, args.warmup, args.duration), flush=True)
        work = local / leg
        dest = result / leg
        work.mkdir()
        dest.mkdir()
        for leaf in ('runtime', 'data', 'tmp'):
            (work / leaf).mkdir()
        # Deliberately do not inherit WINTAP_*, credentials, GC settings, or .NET tuning.
        env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': str(work), 'LANG': 'C.UTF-8',
               'TMPDIR': str(work / 'tmp'), 'DOTNET_ROOT': str(Path(args.dotnet).resolve().parent),
               'DOTNET_PerfMapEnabled': '1', 'COMPlus_PerfMapEnabled': '1',
               'WINTAP_DUCKDB_DIAGNOSTICS': '1', 'WINTAP_CONFIG_PATH': str(config_path),
               'WINTAP_DATA_ROOT': str(work / 'data'), 'WINTAP_RUNTIME_ROOT': str(work / 'runtime'),
               'WINTAP_DISABLE_MCP': '1', 'WINTAP_DISABLE_DUCKDB_UI': '1',
               'WINTAP_DISABLE_SETTINGS': '1', 'WINTAP_DISABLE_ETL': '0',
               'WINTAP_DISABLE_SENSORS': '0', 'WINTAP_ENABLE_DIRECT_PARQUET': '0'}
        if limit:
            env['WINTAP_DUCKDB_RESOLVER_THREADS'] = limit
        log = work / 'runtime/Logs/Lintap.log'
        process = None
        perf = None
        try:
            with open(str(work / 'console.log'), 'w') as console:
                process = subprocess.Popen([args.dotnet, str(app / 'Lintap.dll')], cwd=str(app),
                                           env=env, stdout=console, stderr=subprocess.STDOUT, start_new_session=True)
                deadline = time.monotonic() + 120
                while True:
                    content = text(log)
                    if process.poll() is not None:
                        raise RuntimeError('{} exited at startup; raw log retained locally: {}'.format(leg, work))
                    ready = 'Process database initialized successfully' in content and 'Enabled adapters: 0' in content
                    if limit:
                        ready = ready and 'DuckDB resolver thread limit set to 1' in content
                    if ready:
                        if ('Runtime root: ' + str(work / 'runtime')) not in content or \
                                ('Data root: ' + str(work / 'data')) not in content:
                            raise RuntimeError('Isolated paths not confirmed in startup log.')
                        break
                    if time.monotonic() > deadline:
                        raise RuntimeError('{} startup/thread setting not verified; see local logs in {}'.format(leg, work))
                    time.sleep(1)
                inventory(dest, str(app / 'Lintap.dll'), args.dotnet, process.pid, str(work / 'runtime'))
                (dest / 'verification.json').write_text(json.dumps({
                    'thread_limit': limit or 'unset', 'startup_set_confirmed': bool(limit),
                    'enabled_adapters': 0, 'paths_confirmed': True,
                }, indent=2) + '\n')
                for _ in range(args.warmup):
                    if process.poll() is not None:
                        raise RuntimeError('{} exited during warmup'.format(leg))
                    time.sleep(1)
                perf_file = work / 'perf.data'
                start_time = time.monotonic()
                start_cpu = proc_sample(process.pid)['cpu_ticks']
                hz = os.sysconf('SC_CLK_TCK')
                last_time, last_cpu = start_time, start_cpu
                with open(str(work / 'perf-record.log'), 'w') as perf_log, open(str(dest / 'cpu.csv'), 'w', newline='') as stream:
                    writer = csv.writer(stream)
                    writer.writerow(['elapsed_seconds', 'cpu_cores_interval', 'threads', 'rss_bytes', 'host_load1'])
                    perf = subprocess.Popen(['perf', 'record', '--freq', str(args.frequency), '--call-graph', 'dwarf',
                                             '--pid', str(process.pid), '--output', str(perf_file), '--',
                                             'sleep', str(args.duration)], stdout=perf_log, stderr=subprocess.STDOUT,
                                            start_new_session=True)
                    while perf.poll() is None:
                        if process.poll() is not None:
                            raise RuntimeError('{} exited during measurement'.format(leg))
                        time.sleep(1)
                        now = time.monotonic()
                        sample = proc_sample(process.pid)
                        cores = (sample['cpu_ticks'] - last_cpu) / hz / (now - last_time)
                        writer.writerow([round(now - start_time, 3), round(cores, 4), sample['threads'],
                                         sample['rss_bytes'], os.getloadavg()[0]])
                        last_time, last_cpu = now, sample['cpu_ticks']
                    elapsed = last_time - start_time
                    cpu_seconds = (last_cpu - start_cpu) / hz
                    (dest / 'measurement.json').write_text(json.dumps({
                        'wall_seconds': elapsed, 'cpu_seconds': cpu_seconds,
                        'average_cpu_cores': cpu_seconds / elapsed, 'perf_exit_status': perf.returncode,
                        'measurement_start_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() - elapsed)),
                        'measurement_end_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                    }, indent=2) + '\n')
                if perf.returncode:
                    raise RuntimeError('perf capture failed; see {}'.format(work / 'perf-record.log'))
                # Generate while JIT maps and the running process's native mappings remain available.
                reports(perf_file, work / 'reports', dest / 'reports')
        finally:
            if perf is not None:
                stop_owned(perf)
            if process is not None:
                stop_owned(process)
            aggregate_log(log, dest)
        print('Completed {}; canary stopped.'.format(leg), flush=True)


def publish(result, local, output, owner):
    require_outside_git(output)
    account = pwd.getpwnam(owner)
    group = str(account.pw_gid)
    # chown ONLY this newly created result subtree, not the user's data tree or live state.
    subprocess.run(['chown', '-R', '{}:{}'.format(owner, group), str(result)], check=True)
    subprocess.run(['runuser', '-u', owner, '--', 'mkdir', '-p', '-m', '700', str(output)], check=True)
    destination = Path(output) / local.name
    subprocess.run(['runuser', '-u', owner, '--', 'mkdir', '-m', '700', str(destination)], check=True)
    # Root reads local files: /tmp/opencode may be root-only on this host. Only
    # the extractor accesses NFS, as the owner, so root-squash is also respected.
    producer = subprocess.Popen(['tar', '-C', str(result), '-cf', '-', '.'], stdout=subprocess.PIPE)
    try:
        extracted = subprocess.run(['runuser', '-u', owner, '--', 'tar', '--no-same-owner',
                                    '-C', str(destination), '-xf', '-'], stdin=producer.stdout)
    finally:
        producer.stdout.close()
        producer_status = producer.wait(timeout=30)
    if producer_status or extracted.returncode:
        raise RuntimeError('Report publication failed (tar={}, extraction={}); local reports remain at {}'.format(
            producer_status, extracted.returncode, result))
    subprocess.run(['runuser', '-u', owner, '--', 'chown', '-R', '{}:{}'.format(owner, group), str(destination)], check=True)
    print('Shared results (owned by {}): {}'.format(owner, destination), flush=True)


def require_outside_git(path):
    resolved = Path(path).resolve()
    if any((parent / '.git').exists() for parent in (resolved,) + tuple(resolved.parents)):
        raise RuntimeError('Debug outputs must be outside Git worktrees.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('inventory', 'report-existing', 'compare'))
    parser.add_argument('--owner', required=True, help='Account that owns published aggregate reports')
    parser.add_argument('--output', required=True, help='Aggregate report root outside Git')
    parser.add_argument('--dll', default='', help='Lintap.dll in a complete canary bundle; required for compare')
    parser.add_argument('--dotnet', default=shutil.which('dotnet') or '', help='dotnet executable')
    parser.add_argument('--local-work-root', default='/tmp/opencode', help='Private local disk outside Git')
    parser.add_argument('--runtime-root', default='/var/log/lintap/runtime',
                        help='inventory: filesystem and event-store file sizes only; never opens the database')
    parser.add_argument('--pid', type=int, help='inventory only: inspect selected existing collector without signaling it')
    parser.add_argument('--profile', action='append', default=[], help='report-existing: capture directory (repeatable)')
    parser.add_argument('--duration', type=int, default=300)
    parser.add_argument('--warmup', type=int, default=60)
    parser.add_argument('--frequency', type=int, default=99)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Run with sudo/root; no credentials are read or stored.')
    if args.duration < 1 or args.warmup < 0 or not 1 <= args.frequency <= 1000:
        parser.error('Invalid duration, warmup, or frequency.')
    for command in ('runuser', 'systemctl', 'chown', 'tar', 'findmnt') + (() if args.mode == 'inventory' else ('perf', 'sleep')):
        if not shutil.which(command):
            parser.error('Missing required command: ' + command)
    if args.mode == 'report-existing' and not args.profile:
        parser.error('report-existing requires one or more --profile directories.')
    if args.pid and args.mode != 'inventory':
        parser.error('--pid is for inventory only.')
    def interrupted(signum, frame):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupted)
    pwd.getpwnam(args.owner)
    output = Path(args.output)
    local_root = Path(args.local_work_root)
    require_outside_git(output)
    require_outside_git(local_root)
    os.umask(0o077)
    local_root.mkdir(parents=True, exist_ok=True)
    if run(['findmnt', '-T', str(local_root), '-n', '-o', 'FSTYPE']).stdout.strip() in ('nfs', 'nfs4', 'cifs', 'fuse.vmhgfs-fuse'):
        parser.error('--local-work-root must be local disk, not a shared mount.')
    prefix = 'lintap-{}-'.format(args.mode)
    local = Path(tempfile.mkdtemp(prefix=prefix, dir=str(local_root)))
    result = local / 'results'
    result.mkdir()
    print('Local work/raw data: {}'.format(local), flush=True)
    status = 0
    try:
        inventory(result, args.dll, args.dotnet, args.pid, args.runtime_root)
        if args.mode == 'report-existing':
            for index, directory in enumerate(args.profile, 1):
                source = Path(directory).resolve()
                dest = result / 'profile-{}'.format(index)
                dest.mkdir()
                reports(source / 'perf.data', local / 'profile-{}'.format(index), dest / 'reports')
        elif args.mode == 'compare':
            compare(args, local, result)
        (result / 'status.txt').write_text('complete\n')
    except (Exception, KeyboardInterrupt) as error:
        status = 1
        (result / 'status.txt').write_text('incomplete\n')
        print('ERROR: {}'.format(error or 'interrupted'), file=sys.stderr, flush=True)
    finally:
        print('Publishing reports only; raw perf, console logs, databases, and parquet stay local.', flush=True)
        try:
            publish(result, local, output, args.owner)
        except Exception as error:
            status = 1
            print('ERROR publishing: {}. Retained local reports: {}'.format(error, result), file=sys.stderr, flush=True)
    return status


if __name__ == '__main__':
    sys.exit(main())
