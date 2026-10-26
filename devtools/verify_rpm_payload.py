#!/usr/bin/env python3
"""Read-only RHEL 9 post-install payload check against an independently trusted RPM.

No installation, service control, config reads, tracing or network access. Prints
credential-free JSON; keep output with private pilot evidence, outside Git.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import stat
import subprocess


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def payload_rows(text):
    rows = []
    for line in text.splitlines():
        path, digest, flags, mode = line.split('\t')
        if not Path(path).is_absolute(): raise ValueError('Nonabsolute RPM payload path')
        if stat.S_ISREG(int(mode, 8)) and not int(flags) & 1:  # RPMFILE_CONFIG
            if len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
                raise ValueError('Missing/non-SHA256 regular payload digest')
            rows.append((Path(path), digest))
    if not rows: raise ValueError('No verifiable payload')
    return rows


def rpm(*args):
    return subprocess.run(['rpm', *args], check=True, capture_output=True, text=True, timeout=30).stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rpm', required=True, type=Path)
    parser.add_argument('--rpm-sha256', required=True, help='From independently reviewed native build record')
    args = parser.parse_args()
    release = platform.freedesktop_os_release()
    if release.get('ID') != 'rhel' or release.get('VERSION_ID', '').split('.')[0] != '9' or platform.machine() != 'x86_64':
        parser.error('This gate targets native RHEL 9 x86_64')
    if sha256(args.rpm) != args.rpm_sha256: raise ValueError('Trusted RPM hash mismatch')
    artifact = str(args.rpm.resolve())
    name = rpm('-qp', '--qf', '%{NAME}', artifact)
    if name != 'lintap': raise ValueError('Expected lintap package')
    fmt = '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}'
    nevra = rpm('-qp', '--qf', fmt, artifact)
    if rpm('-q', '--qf', fmt, name) != nevra: raise ValueError('Installed package differs from reviewed RPM')
    if rpm('-qp', '--qf', '%{ARCH}:%{FILEDIGESTALGO}', artifact) != 'x86_64:8':
        raise ValueError('Require native x86_64 RPM with SHA256 file digests')
    rows = payload_rows(rpm('-qp', '--qf', '[%{FILENAMES}\t%{FILEDIGESTS}\t%{FILEFLAGS}\t%{FILEMODES:octal}\n]', artifact))
    mismatches = []
    for path, digest in rows:
        if path.is_symlink() or not path.is_file() or sha256(path) != digest:
            mismatches.append(str(path))
    objects = {}
    for key in ('network_ops_tracer.bpf.o', 'file_ops_tracer.bpf.o', 'Lintap.dll', 'WintapAPI.dll'):
        found = [(path, digest) for path, digest in rows if path.name == key]
        if len(found) != 1: raise ValueError('Required managed/core payload missing or ambiguous')
        objects[key] = found[0][1]
    print(json.dumps(dict(scope='Installed payload vs trusted RPM; not live capture acceptance',
        package=nevra, rpm_sha256=args.rpm_sha256, checked_files=len(rows),
        passed=not mismatches, mismatches=mismatches, payload_sha256=objects), indent=2))
    return int(bool(mismatches))


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.SubprocessError):
        print('Package provenance unavailable or mismatched; no acceptance (details suppressed)')
        raise SystemExit(1)
