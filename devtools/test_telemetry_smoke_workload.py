"""Stdlib regression tests; run on Linux with python3 -m unittest -v this_file."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux workload")
class TelemetryWorkloadTests(unittest.TestCase):
    def test_small_all_domain_run_and_existing_directory_safety(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "run"
            command = [sys.executable, str(Path(__file__).with_name("telemetry_smoke_workload.py")),
                       "--output", str(output), "--hold", "0.01", "--manifest", str(Path(directory) / "run.json")]
            result = subprocess.run(command, capture_output=True, text=True, timeout=45)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            manifest = json.loads((output / "manifest.json").read_text())
            portable = json.loads((Path(directory) / "run.json").read_text())
            self.assertEqual(portable["test"], "telemetry-workload")
            self.assertTrue(portable["selectors"])
            self.assertTrue(portable["host"]["hostname"])
            self.assertTrue(manifest["stimulusOnly"])
            generated = {row["case"] for row in manifest["cases"] if row["status"] == "generated"}
            self.assertEqual(generated, {"wt_fork", "wt_forkexec", "wt_spawn", "wt_threads", "wt_file", "tcp-ipv4", "udp-ipv4"})
            events = manifest["events"]
            self.assertTrue(any(row["case"] == "wt_forkchild" and row.get("noExec") for row in events))
            thread = next(row for row in events if row["case"] == "wt_thread")
            self.assertNotEqual(thread["pid"], thread["tid"])
            self.assertFalse(thread["expectedProcessStart"])
            expected = set()
            for row in events:
                expected.update(row.get("expectedActivities", []))
                if row.get("expectedActivity"):
                    expected.add(row["expectedActivity"])
            self.assertTrue({"Open", "Read", "Write", "Close", "Delete", "Start", "Stop",
                             "TcpIpConnect", "TcpIpAccept", "TcpIpSend", "TcpIpRecv", "TcpIpDisconnect",
                             "UdpIpSend", "UdpIpRecv"} <= expected)
            self.assertFalse(list((output / "files").rglob("*.bin")))
            original = (output / "manifest.json").read_bytes()
            second = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(second.returncode, 0)
            self.assertEqual((output / "manifest.json").read_bytes(), original)

    def test_missing_native_helper_is_failure_not_silent_skip(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "run"
            result = subprocess.run([sys.executable, str(Path(__file__).with_name("telemetry_smoke_workload.py")),
                                     "--output", str(output), "--clone-helper", "/nonexistent/wintap-helper", "--hold", "0",
                                     "--manifest", str(Path(directory) / "run.json")],
                                    capture_output=True, text=True, timeout=45)
            self.assertEqual(result.returncode, 1)
            manifest = json.loads((output / "manifest.json").read_text())
            native = next(row for row in manifest["cases"] if row["case"] == "native-clone-families")
            self.assertEqual(native["status"], "failed")


if __name__ == "__main__":
    unittest.main()
