#!/usr/bin/env python3
"""Isolated Linux A/B rounds. Never install/restart the system service.

Run as root on lintap-dev with native --qa-root and mounted --data-root.
Uses a copy of the installed package as historical-code control, not old recordings.
"""
import argparse
import ctypes
import datetime as dt
import hashlib
import json
import os
import platform
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def workload(root, multiplier):
    root.mkdir(parents=True)
    records = []
    children = []
    started = time.time_ns()
    for cohort, count, hold, files in [('fast', 20, .005, 2), ('medium', 8, .2, 4),
                                      ('long', 4, 1.3, 4), ('burst', 10, .005, 200)]:
        for index in range(count * multiplier):
            pid = os.fork()
            if pid == 0:
                try:
                    ctypes.CDLL(None).prctl(15, ('qa_' + cohort).encode(), 0, 0, 0)
                    me = os.getpid()
                    fields = Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()
                    start_ticks = int(fields[19])
                    begin = time.monotonic_ns()
                    payload = root / 'payload' / f'{cohort}-{me}'
                    payload.mkdir(parents=True)
                    for f in range(files):
                        p = payload / f'file-{f}.txt'
                        p.write_bytes(b'evidence-' * 16)
                        p.read_bytes()
                    time.sleep(hold)
                    record = dict(pid=me, parent=os.getppid(), cohort=cohort,
                                  executable=str(Path('/proc/self/exe').resolve()),
                                  start_ticks=start_ticks, clock_ticks=os.sysconf('SC_CLK_TCK'),
                                  callback_begin_monotonic_ns=begin, before_exit_monotonic_ns=time.monotonic_ns(),
                                  requested_hold_s=hold, payload_files=files)
                    (root / f'child-{me}.json').write_text(json.dumps(record))
                    os._exit(0)
                except BaseException:
                    os._exit(1)
            children.append(pid)
    for pid in children:
        _, status = os.waitpid(pid, 0)
        record = json.loads((root / f'child-{pid}.json').read_text()) if (root / f'child-{pid}.json').exists() else dict(pid=pid)
        record.update(wait_status=status, reap_monotonic_ns=time.monotonic_ns())
        records.append(record)
    manifest = dict(start_unix_ns=started, end_unix_ns=time.time_ns(), children=records,
                    expected_children=len(children), expected_payload_files=sum(r.get('payload_files', 0) for r in records))
    (root / 'workload.json').write_text(json.dumps(manifest, indent=2))
    if any(r['wait_status'] != 0 for r in records):
        raise RuntimeError('Workload child failure')
    return manifest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--qa-root', type=Path, required=True)
    parser.add_argument('--data-root', type=Path, required=True)
    parser.add_argument('--fixed-bin', type=Path, required=True)
    parser.add_argument('--rounds', help='Comma-separated subset; default runs the original six rounds')
    parser.add_argument('--settle-seconds', type=float, default=30,
                        help='Post-workload normal ETL settling time before shutdown')
    parser.add_argument('--experiment-batch-drain', action='store_true',
                        help='Opt in to candidate post-producer-stop Esper window drain')
    parser.add_argument('--shutdown-timeout', type=float, default=45,
                        help='Seconds allowed for collector graceful shutdown before recording forced termination')
    parser.add_argument('--candidate-self-contained', action='store_true',
                        help='Launch the candidate apphost rather than the system dotnet host')
    parser.add_argument('--stop-signal', choices=['SIGINT', 'SIGTERM'], default='SIGINT',
                        help='Record an explicit graceful-stop signal; SIGTERM matches installed-host testing')
    parser.add_argument('--experiment-exit-recovery', action='store_true',
                        help='Retain authoritative exit-only identity in the bounded historical cache; no synthetic Start')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Run as root for eBPF privileges')
    args.qa_root.mkdir(parents=True, exist_ok=True)
    # Refuse previous run evidence; copies contain private working-directory state.
    package = args.qa_root / 'package-bin'
    fixed = args.qa_root / 'fixed-bin'
    shutil.copytree('/usr/lib/lintap', package)
    shutil.copytree(args.fixed_bin, fixed)
    boot = int(next(line.split()[1] for line in Path('/proc/stat').read_text().splitlines() if line.startswith('btime ')))
    (args.qa_root / 'host-provenance.json').write_text(json.dumps(dict(
        boot_unix_seconds=boot, hostname=platform.node(), kernel=platform.release(),
        arch=platform.machine(), os_release=Path('/etc/os-release').read_text()), indent=2))
    service = lambda: subprocess.check_output(['systemctl', 'show', 'lintap', '-p', 'MainPID', '-p', 'NRestarts'], text=True)
    results = dict(start_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
                   installed_service_before=service(), package_dll_sha256=sha(package / 'Lintap.dll'),
                   fixed_dll_sha256=sha(fixed / 'Lintap.dll'), rounds=[])
    (args.qa_root / 'session.json').write_text(json.dumps(results, indent=2))
    specs = [('package-normal', package, False, 1), ('package-missing-birth', package, True, 1),
             ('fixed-normal', fixed, False, 1), ('fixed-missing-birth', fixed, True, 1),
             ('fixed-burst', fixed, False, 2), ('fixed-restart', fixed, False, 1)]
    if args.rounds:
        selected = args.rounds.split(',')
        if 'fixed-batch-drain' in selected:
            specs.append(('fixed-batch-drain', fixed, True, 1))
        if 'fixed-legacy-exit' in selected:
            fallback = args.qa_root / 'fixed-fallback-bin'
            shutil.copytree(fixed, fallback)
            objects = list(fallback.rglob('exit_tracer.bpf.o'))
            if len(objects) != 1:
                raise RuntimeError('Expected exactly one copied exit object')
            # Deliberate ABI fault: use the 48-byte no-task-start tracepoint object
            # under the normal candidate name; only this private copy is changed.
            shutil.copyfile(objects[0].with_name('exit_tracepoint.bpf.o'), objects[0])
            specs.append(('fixed-legacy-exit', fallback, True, 1))
        unknown = set(selected) - {s[0] for s in specs}
        if unknown:
            raise ValueError('Unknown rounds: ' + ','.join(sorted(unknown)))
        specs = [s for s in specs if s[0] in selected]
    for index, (name, binary, missing_birth, multiplier) in enumerate(specs):
        qa = args.qa_root / name
        qa.mkdir()
        data = args.data_root / name
        runtime = args.qa_root / ('shared-fixed-runtime' if index >= 4 else name + '-runtime')
        env = os.environ.copy()
        env.update(WINTAP_DATA_ROOT=str(data), WINTAP_RUNTIME_ROOT=str(runtime),
                   WINTAP_DISABLE_MCP='true', WINTAP_DISABLE_DUCKDB_UI='true',
                   WINTAP_ETL_SERIALIZATION_INTERVAL_SEC='10', WINTAP_ETL_UPLOAD_INTERVAL_SEC='15',
                   WINTAP_ENABLE_NETWORK_SENSOR='false', WINTAP_ENABLE_SELINUX_SENSOR='false')
        env['WINTAP_EXPERIMENT_LIFECYCLE_SHADOW_PATH'] = str(qa / 'lifetime-shadow.jsonl')
        env['WINTAP_EXPERIMENT_EXIT_IDENTITY_RECOVERY'] = str(args.experiment_exit_recovery).lower()
        if args.experiment_batch_drain or name == 'fixed-batch-drain':
            env['WINTAP_EXPERIMENT_DRAIN_BATCH_WINDOWS'] = 'true'
        if missing_birth:
            env.update(WINTAP_ENABLE_CLONE_SENSOR='false', WINTAP_ENABLE_EXECVE_SENSOR='false',
                       WINTAP_ENABLE_PROCESS_RUNDOWN_SENSOR='false')
        result = dict(round=index, name=name, missing_birth_injection=missing_birth, data_root=str(data),
                      runtime_root=str(runtime), qa_root=str(qa), env_overrides={k: v for k, v in env.items() if k.startswith('WINTAP_')})
        result.update(settle_seconds=args.settle_seconds, shutdown_timeout_seconds=args.shutdown_timeout,
                       stop_signal=args.stop_signal, candidate_self_contained=args.candidate_self_contained,
                       experiment_exit_recovery=args.experiment_exit_recovery,
                      legacy_exit_injection=name == 'fixed-legacy-exit',
                      binary_sha256=sha(binary / 'Lintap.dll'),
                      exit_object_sha256={str(p.relative_to(binary)): sha(p) for p in binary.rglob('exit_tracer.bpf.o')})
        with (qa / 'collector.log').open('w') as log:
            executable = [str(binary / 'Lintap')] if binary == package or args.candidate_self_contained else ['/usr/local/bin/dotnet', str(binary / 'Lintap.dll')]
            proc = subprocess.Popen(executable, cwd=binary, env=env, stdout=log, stderr=subprocess.STDOUT)
            try:
                time.sleep(20)
                if proc.poll() is not None:
                    raise RuntimeError('Collector exited early: ' + str(proc.returncode))
                effective = dict(field.split('=', 1) for field in
                                 Path(f'/proc/{proc.pid}/environ').read_bytes().decode().split('\0')
                                 if '=' in field and field.startswith('WINTAP_'))
                result['effective_environment'] = effective
                if any(effective.get(k) != v for k, v in result['env_overrides'].items()):
                    raise RuntimeError('Collector effective WINTAP environment does not match requested configuration')
                result['workload'] = workload(qa / 'workload', multiplier)
                time.sleep(args.settle_seconds)
            except Exception as exc:
                result['error'] = str(exc)
            finally:
                if proc.poll() is None:
                    proc.send_signal(getattr(signal, args.stop_signal))
                    try:
                        proc.wait(timeout=args.shutdown_timeout)
                    except subprocess.TimeoutExpired:
                        result['forced_termination'] = True
                        proc.terminate()
                        try:
                            proc.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                            proc.wait()
                result['collector_exit_code'] = proc.returncode
        state = runtime / 'wintapstate.json'
        if state.exists():
            result['agent_state'] = json.loads(state.read_text())
        results['rounds'].append(result)
        (args.qa_root / 'session.json').write_text(json.dumps(results, indent=2))
        print(json.dumps({k: v for k, v in result.items() if k != 'workload'}), flush=True)
        if result.get('error') or result.get('forced_termination'):
            break
    results.update(installed_service_after=service(), end_utc=dt.datetime.now(dt.timezone.utc).isoformat())
    (args.qa_root / 'session.json').write_text(json.dumps(results, indent=2))
    if len(results['rounds']) != len(specs) or any(r.get('collector_exit_code') != 0 for r in results['rounds']):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
