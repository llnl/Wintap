import unittest
from unittest.mock import patch

import network_capture_smoke_test as capture

from network_endpoint_smoke_test import host_address, generate_cases, validate_rows


def fixture(same_pid):
    selector = dict(case="same-process" if same_pid else "separate-processes", pids=[101] if same_pid else [101, 202],
                    endpointExpectations=[
                        dict(role="server", pid=101, localIp="192.168.252.40", remoteIp="192.168.252.40", localPort=41000, remotePort=51000),
                        dict(role="client", pid=101 if same_pid else 202, localIp="192.168.252.40", remoteIp="192.168.252.40", localPort=51000, remotePort=41000)])
    rows = []
    for end in selector["endpointExpectations"]:
        for inbound in (False, True):
            rows.append(dict(pid=end["pid"], pid_hash=f"identity-{end['pid']}",
                             activity="tcpiprecv" if inbound else "tcpipsend",
                             local_ip=end["localIp"], local_port=end["localPort"],
                             remote_ip=end["remoteIp"], remote_port=end["remotePort"],
                             source_port=end["remotePort"] if inbound else end["localPort"],
                             destination_port=end["localPort"] if inbound else end["remotePort"]))
    return selector, rows


class EndpointSmokeTests(unittest.TestCase):
    def test_both_identity_cases_pass(self):
        for same_pid in (True, False):
            selector, rows = fixture(same_pid)
            self.assertEqual("passed", validate_rows(rows, selector)["status"])

    def test_reversed_receive_detected_even_when_same_process_owns_both_ends(self):
        for same_pid in (True, False):
            selector, rows = fixture(same_pid)
            for row in rows:
                if row["activity"] == "tcpiprecv":
                    row["local_port"], row["remote_port"] = row["remote_port"], row["local_port"]
            result = validate_rows(rows, selector)
            self.assertEqual("failed", result["status"])
            self.assertEqual(2, len(result["violations"]))

    def test_missing_receive_is_not_a_pass(self):
        selector, rows = fixture(True)
        result = validate_rows([r for r in rows if r["activity"] == "tcpipsend"], selector)
        self.assertEqual("pending", result["status"])

    def test_missing_directed_provenance_is_not_a_pass(self):
        selector, rows = fixture(True)
        for row in rows:
            row["source_port"] = row["destination_port"] = None
        self.assertEqual("pending", validate_rows(rows, selector)["status"])

    def test_pid_hash_distinguishes_processes(self):
        selector, rows = fixture(False)
        for row in rows:
            row["pid_hash"] = "same-identity"
        self.assertEqual("failed", validate_rows(rows, selector)["status"])

    def test_missing_hash_is_not_a_pass(self):
        selector, rows = fixture(True)
        rows[0]["pid_hash"] = None
        self.assertEqual("failed", validate_rows(rows, selector)["status"])

    def test_loopback_is_rejected_for_this_workload(self):
        self.assertRaises(ValueError, host_address, "127.0.0.1")

    def test_real_workload_generates_both_process_topologies(self):
        try:
            ip = host_address()
        except OSError as error:
            self.skipTest(f"No routable host interface: {error}")
        selectors = generate_cases(ip)
        self.assertEqual(2, len(selectors[0]["pids"]))
        self.assertEqual(1, len(selectors[1]["pids"]))
        for selector in selectors:
            server, client = selector["endpointExpectations"]
            self.assertEqual(server["localPort"], client["remotePort"])
            self.assertEqual(server["remotePort"], client["localPort"])
            self.assertNotEqual(server["localPort"], client["localPort"])
            self.assertEqual(ip, server["localIp"])

    def capture_main(self, options):
        with patch("sys.argv", ["network_capture_smoke_test.py", "--data-root", "/unused", *options]), \
             patch.object(capture, "generate_traffic"), \
             patch.object(capture, "generate_udp_traffic", return_value=[("8.8.8.8", 53, True, None)]), \
             patch.object(capture, "find_candidate_parquet_files", return_value=["unused.parquet"]), \
             patch.object(capture, "query_parquet", return_value=[{"remote_port": 53}]), \
             patch.object(capture, "validate", return_value=0), \
             patch.object(capture, "record") as record, \
             patch("network_endpoint_smoke_test.run_checks", return_value=0) as endpoint_check:
            self.assertEqual(0, capture.main.__wrapped__())
            return endpoint_check.called, record.call_args_list

    def test_normal_network_smoke_confirms_endpoints_by_default(self):
        called, records = self.capture_main([])
        self.assertTrue(called)
        self.assertTrue(any(call.kwargs.get("endpointChecksRequested") is True for call in records))

    def test_endpoint_opt_out_is_explicitly_recorded(self):
        called, records = self.capture_main(["--no-verify-endpoints"])
        self.assertFalse(called)
        self.assertTrue(any(call.kwargs.get("endpointChecksRequested") is False for call in records))


if __name__ == "__main__":
    unittest.main()
