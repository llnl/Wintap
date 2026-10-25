"""Synthetic/source guards; actual-object qualification is separate and opt-in."""
from pathlib import Path
import unittest

from network_trace_smoke_test import check_rows


class NetworkTraceTests(unittest.TestCase):
    def row(self, operation=7, size=3):
        return dict(operation=str(operation), protocol='6' if operation == 2 else '17', bytes=str(size), source='127.0.0.1', source_port='1234',
            destination='127.0.0.1', destination_port='4321')

    def expected(self, operation=7, size=3):
        return [('fixture', operation, ('127.0.0.1', 1234), ('127.0.0.1', 4321), size)]

    def test_complete_success(self):
        self.assertFalse(check_rows([self.row()], self.expected()))

    def test_missing_and_duplicate_receive(self):
        self.assertTrue(check_rows([], self.expected()))
        self.assertTrue(check_rows([self.row(), self.row()], self.expected()))

    def test_wrong_return_bytes_and_zero_datagram(self):
        self.assertTrue(check_rows([self.row(size=4294967285)], self.expected()))
        self.assertFalse(check_rows([self.row(size=0)], self.expected(size=0)))

    def test_extra_accept_and_send_are_not_waived(self):
        self.assertTrue(check_rows([self.row(operation=2)], []))
        self.assertTrue(check_rows([self.row(operation=6)], []))

    def test_operation_does_not_waive_wrong_protocol(self):
        row = self.row(); row['protocol'] = '6'
        self.assertTrue(check_rows([row], self.expected()))

    def test_current_source_has_success_and_pointer_domain_guards(self):
        source = (Path(__file__).parents[1] / 'wintap/platform/linux/sensor/ebpf/tracers/network_ops_tracer.bpf.c').read_text()
        receive = source.split('int kretprobe__udp_recvmsg(', 1)[1].split('// TCP connect', 1)[0]
        send = source.split('int kretprobe__udp_sendmsg(', 1)[1].split('// udp_recvmsg', 1)[0]
        accept = source.split('int kretprobe__inet_csk_accept(', 1)[1].split('// Capture TCP send', 1)[0]
        self.assertIn('NET_OP_TCP_ACCEPT', accept)
        self.assertIn('ci.daddr, ci.saddr, ci.dport, ci.sport', accept)
        self.assertIn('(__u64)-4095', accept)
        for body in (receive, send):
            self.assertIn('(int)PT_REGS_RC(ctx)', body)
            self.assertIn('ret < 0', body)
        self.assertIn('bpf_probe_read_kernel', receive)
        self.assertNotIn('bpf_probe_read_user', receive)
        self.assertNotIn('namelen < sizeof(peer)', receive)
        self.assertNotIn('ret <= 0', receive)


if __name__ == '__main__':
    unittest.main()
