#!/usr/bin/env python3
"""Bounded actual-object qualification, NOT a recurring canary or ETL acceptance.

Run only on a designated idle Linux VM. The runner attaches tracers for this PID,
never modifies services/settings, and exits after a hard bounded duration.
Raw traces, endpoint selectors and summaries stay in a fresh VM-local output dir.
"""
import argparse
import csv
from collections import Counter
import ctypes
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import time


def check_rows(rows, expectations):
    failures = []
    for label, operation, source, destination, size in expectations:
        matching = [r for r in rows if int(r['operation']) == operation and
            int(r['protocol']) == (17 if operation in (6, 7) else 6) and
            (r['source'], int(r['source_port'])) == source and
            (r['destination'], int(r['destination_port'])) == destination]
        if len(matching) != 1 or (size is not None and int(matching[0]['bytes']) != size):
            failures.append(label)
    # UDP uses successful returned-byte semantics. Failed sends/receives have
    # no row; every UDP observation must be accounted for, including zero bytes.
    wanted = sum(op in (6, 7) for _, op, _, _, _ in expectations)
    if sum(int(r['operation']) in (6, 7) for r in rows) != wanted:
        failures.append('unexpected/duplicate UDP observations')
    if sum(int(r['operation']) == 2 for r in rows) != sum(op == 2 for _, op, _, _, _ in expectations):
        failures.append('unexpected/duplicate TCP Accept observations')
    return failures


def receive_batch(sock):
    """One queued datagram through libc recvmmsg; no extra syscall tracer needed."""
    class Iovec(ctypes.Structure):
        _fields_ = [('base', ctypes.c_void_p), ('length', ctypes.c_size_t)]
    class Msghdr(ctypes.Structure):
        _fields_ = [('name', ctypes.c_void_p), ('namelen', ctypes.c_uint), ('iov', ctypes.POINTER(Iovec)),
            ('iovlen', ctypes.c_size_t), ('control', ctypes.c_void_p), ('controllen', ctypes.c_size_t), ('flags', ctypes.c_int)]
    class Mmsghdr(ctypes.Structure):
        _fields_ = [('header', Msghdr), ('length', ctypes.c_uint)]
    payload, peer = ctypes.create_string_buffer(64), ctypes.create_string_buffer(128)
    iov = Iovec(ctypes.cast(payload, ctypes.c_void_p), 64)
    message = Mmsghdr(Msghdr(ctypes.cast(peer, ctypes.c_void_p), 128, ctypes.pointer(iov), 1, None, 0, 0), 0)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.recvmmsg.argtypes = [ctypes.c_int, ctypes.POINTER(Mmsghdr), ctypes.c_uint, ctypes.c_int, ctypes.c_void_p]
    libc.recvmmsg.restype = ctypes.c_int
    if libc.recvmmsg(sock.fileno(), ctypes.byref(message), 1, 0, None) != 1:
        raise OSError(ctypes.get_errno(), 'recvmmsg failed')
    return payload.raw[:message.length]


def stimulus():
    expected = []
    with socket.socket() as listener, socket.socket() as client:
        listener.bind(('127.0.0.1', 0)); listener.listen(1)
        listener.setblocking(False)
        try:
            listener.accept()
            raise AssertionError('nonblocking accept unexpectedly succeeded')
        except BlockingIOError:
            pass
        listener.setblocking(True)
        client.connect(listener.getsockname())
        server, _ = listener.accept()
        with server:
            expected.append(('TCP Accept', 2, client.getsockname(), server.getsockname(), 0))
            client.sendall(b'hello'); assert server.recv(5) == b'hello'
            server.sendall(b'world'); assert client.recv(5) == b'world'
    # Separate sockets/mode labels ensure connected Receive cannot satisfy
    # unconnected coverage. Pause respects retained one-second pointer sampling.
    for mode, payload in (('recvfrom', b'one'), ('recvmsg', b'two'), ('connected', b'three'),
                          ('zero', b''), ('truncated', b'abcdefgh'), ('sendmsg', b'four'),
                          ('recvmmsg', b'batch')):
        time.sleep(1.1)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
            receiver.bind(('127.0.0.1', 0)); receiver.settimeout(2)
            if mode == 'connected':
                sender.bind(('127.0.0.1', 0)); sender.connect(receiver.getsockname())
                receiver.connect(sender.getsockname())
            # Failed receive must neither emit nor consume connected sampling.
            receiver.setblocking(False)
            try:
                receiver.recv(16)
                raise AssertionError('empty receive unexpectedly succeeded')
            except BlockingIOError:
                pass
            receiver.settimeout(2)
            if mode == 'sendmsg':
                sent = sender.sendmsg([payload], [], 0, receiver.getsockname())
            else:
                sent = sender.send(payload) if mode == 'connected' else sender.sendto(payload, receiver.getsockname())
            assert sent == len(payload)
            src, dest = sender.getsockname(), receiver.getsockname()
            if src[0] == '0.0.0.0':
                src = ('127.0.0.1', src[1])  # Stimulus sends exclusively to loopback.
            expected.append((mode + ' Send', 6, src, dest, len(payload)))
            if mode == 'recvmsg':
                data, _, _, peer = receiver.recvmsg(32)
            elif mode == 'connected':
                data = receiver.recv(32)
            elif mode == 'recvmmsg':
                data = receive_batch(receiver)
            else:
                data, peer = receiver.recvfrom(3 if mode == 'truncated' else 32)
            assert data == (payload[:3] if mode == 'truncated' else payload)
            expected.append((mode + ' Receive', 7, src, dest, len(data)))
            # A too-large send reaches udp_sendmsg but must not emit a success.
            try:
                sender.sendto(b'x' * 65508, dest)
                raise AssertionError('oversize UDP unexpectedly succeeded')
            except OSError:
                pass
    return expected


def turnover_stimulus():
    """Small sequential loop, not pressure: first sample in each new lifetime.

    Connected sockets repeat within one second to check intentional sampling;
    no pause between lifetimes masks inherited pointer-keyed sample state.
    """
    expected, tuples = [], set()
    start = time.monotonic()
    for index in range(24):
        connected = index % 2 == 0
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
            sender.bind(('127.0.0.1', 0)); receiver.bind(('127.0.0.1', 0))
            src, dest = sender.getsockname(), receiver.getsockname()
            assert (src, dest) not in tuples, 'ephemeral tuple reused; repeat qualification'
            tuples.add((src, dest))
            if connected:
                sender.connect(dest); receiver.connect(src)
            receiver.setblocking(False)
            try:
                receiver.recv(32)
                raise AssertionError('empty receive unexpectedly succeeded')
            except BlockingIOError:
                pass
            try:
                sender.sendto(b'x' * 65508, dest)
                raise AssertionError('oversize send unexpectedly succeeded')
            except OSError:
                pass
            receiver.settimeout(1)
            begun = time.monotonic()
            for repeat in range(2 if connected else 1):
                payload = b'first' if repeat == 0 else b'sampled'
                assert sender.sendto(payload, dest) == len(payload)
                data = receiver.recv(32) if connected else receiver.recvfrom(32)[0]
                assert data == payload
            assert time.monotonic() - begun < .9, 'sampling interval crossed; repeat qualification'
            expected.extend([(f'lifetime-{index} Send', 6, src, dest, 5),
                             (f'lifetime-{index} Receive', 7, src, dest, 5)])
    assert time.monotonic() - start < 5, 'turnover workload exceeded bound'
    return expected


def tcp_lifecycle_stimulus():
    """Data, half-close, sampled EOF and delayed EOF with exact socket roles."""
    expected = []
    with socket.socket() as listener, socket.socket() as client:
        listener.bind(('127.0.0.1', 0)); listener.listen(1); listener.settimeout(2)
        client.settimeout(2); client.connect(listener.getsockname())
        server, _ = listener.accept()
        with server:
            server.settimeout(2)
            c, s = client.getsockname(), server.getsockname()
            expected.extend([('Accept', 2, c, s, 0)])
            client.sendall(b'hello'); assert server.recv(5) == b'hello'
            server.sendall(b'world'); assert client.recv(5) == b'world'
            expected.extend([('client Send', 3, c, s, 5), ('server Receive', 4, c, s, 5),
                             ('server Send', 3, s, c, 5), ('client Receive', 4, s, c, 5)])
            # State transitions must not reset the per-direction sample clock.
            server.shutdown(socket.SHUT_WR); client.shutdown(socket.SHUT_WR)
            assert client.recv(1) == b''; assert server.recv(1) == b''
            time.sleep(1.1)
            # EOF is still an entry request of one byte, not one received byte.
            assert client.recv(1) == b''; assert server.recv(1) == b''
            expected.extend([('delayed client EOF request', 4, s, c, 1),
                             ('delayed server EOF request', 4, c, s, 1),
                             ('server Disconnect', 5, s, c, 0), ('client Disconnect', 5, c, s, 0)])
        # Listener close has no peer by definition; assert its own separate tuple.
        expected.append(('listener Close', 5, s, ('0.0.0.0', 0), 0))
    return expected


def check_tcp_lifecycle(rows, expected):
    def key(operation, source, destination, size):
        return (int(operation), source[0], int(source[1]), destination[0], int(destination[1]), int(size))
    wanted = Counter(key(op, src, dst, size) for _, op, src, dst, size in expected)
    # Connection-entry duplicates are a separate pre-existing contract; all
    # Accept/Send/Recv/Close rows, including partial extra rows, are strict here.
    got = Counter(key(r['operation'], (r['source'], r['source_port']),
        (r['destination'], r['destination_port']), r['bytes']) for r in rows if int(r['operation']) != 1)
    failures = []
    if any(int(r['protocol']) != 6 for r in rows): failures.append('unexpected protocol')
    if wanted - got: failures.append('missing/wrong TCP lifecycle observations')
    if got - wanted: failures.append('extra/duplicate/partial TCP lifecycle observations')
    return failures


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--runner', required=True, type=Path)
    p.add_argument('--object', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--baseline', action='store_true', help='Compare an old object; missing new send-return map/hook allowed, checks remain strict')
    p.add_argument('--turnover', action='store_true', help='24 rapid socket lifetimes; connected repeats must remain sampled')
    p.add_argument('--tcp-lifecycle', action='store_true', help='Strict half-close/EOF/close tuple and sampling regression')
    args = p.parse_args()
    if args.turnover and args.tcp_lifecycle: p.error('Select one qualification workload')
    args.output.mkdir(parents=True, exist_ok=False)
    ready, trace = args.output / 'ready', args.output / 'trace.csv'
    with (args.output / 'runner.log').open('w') as log:
        # Outer deadline includes load/attachment/cleanup, with forced teardown
        # if graceful exit stalls. timeout closes only this observer's links.
        command = ['sudo', '-n', 'timeout', '--signal=TERM', '--kill-after=2s', '25s',
            str(args.runner.resolve()), str(args.object.resolve()),
            str(trace.resolve()), str(ready.resolve()), str(os.getpid()), '20']
        if args.baseline:
            command.append('--baseline')
        proc = subprocess.Popen(command, stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 5
            while not ready.exists():
                if proc.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError('Actual-object runner did not reach attached readiness')
                time.sleep(.05)
            expected = tcp_lifecycle_stimulus() if args.tcp_lifecycle else turnover_stimulus() if args.turnover else stimulus()
            rc = proc.wait(timeout=30)
            if rc: raise RuntimeError(f'Runner failed/unclean context maps: {rc}')
        finally:
            if proc.poll() is None:
                # Runner has its own bound; do not kill unrelated processes.
                proc.wait(timeout=30)
    rows = list(csv.DictReader(trace.open()))
    rows = [r for r in rows if int(r['pid']) == os.getpid()]
    failures = check_tcp_lifecycle(rows, expected) if args.tcp_lifecycle else check_rows(rows, expected)
    result = dict(scope='actual CO-RE object only; not managed/ETL/package acceptance',
        object_sha256=hashlib.sha256(args.object.read_bytes()).hexdigest(),
        checks=len(expected), mode='tcp-lifecycle' if args.tcp_lifecycle else 'turnover' if args.turnover else 'return-matrix',
        failures=failures, passed=not failures)
    (args.output / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: v for k, v in result.items() if k != 'object_sha256'}))
    return bool(failures)


if __name__ == '__main__':
    raise SystemExit(main())
