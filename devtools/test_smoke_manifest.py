import json
from pathlib import Path
import sys
import tempfile
import unittest
import datetime as dt
from unittest.mock import patch

from smoke_manifest import smoke_run, record
from smoke_parquet import publish


class ManifestTests(unittest.TestCase):
    def test_parquet_lifecycle_default_env_failure_and_opt_out(self):
        import duckdb
        for fail, opt_out in ((False, False), (True, False), (False, True)):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest = root / "run.json"
                @smoke_run("file-capture")
                def workload():
                    record(selectors=[dict(domain="file", pids=[42], paths=["/qa/test"])])
                    record(results={"check": True})
                    if fail:
                        raise SystemExit(2)
                    return 0
                argv = ["test", "--manifest", str(manifest)] + (["--no-smoke-parquet"] if opt_out else [])
                with patch.dict("os.environ", {"WINTAP_DATA_ROOT": str(root)}), patch.object(sys, "argv", argv):
                    if fail:
                        with self.assertRaises(SystemExit):
                            workload()
                    else:
                        workload()
                files = list(root.rglob("*.parquet"))
                self.assertEqual(len(files), 0 if opt_out else 3)
                self.assertFalse(list(root.rglob("*.active")))
                if not opt_out:
                    with duckdb.connect() as con:
                        rows = con.execute("SELECT revision, phase, outcome, manifest_json FROM read_parquet(?) ORDER BY revision", [[str(f) for f in files]]).fetchall()
                    self.assertEqual([r[1] for r in rows], ["started", "stimulus-complete", "finished"])
                    self.assertEqual(rows[-1][2], "failed" if fail else "passed")
                    self.assertEqual(json.loads(rows[-1][3]), json.loads(manifest.read_text()))

    def test_explicit_root_and_export_failure_keep_workload_outcome(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "run.json"
            @smoke_run("file-capture")
            def workload():
                self.assertEqual(sys.argv, ["test"])
                return 0
            with patch.object(sys, "argv", ["test", "--manifest=" + str(path), "--smoke-data-root=" + directory]), patch("smoke_parquet.publish", side_effect=OSError("unwritable")):
                workload()
            value = json.loads(path.read_text())
            self.assertEqual(value["status"], "passed")
            self.assertEqual(value["durableExportError"], "unwritable")
            self.assertEqual(value["smokeEvidenceRevision"], 2)

    def test_partition_utc_and_identical_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            value = dict(smokeManifestVersion=1, runId="test-run", test="file-capture", host={"hostname": "host/a"},
                         startedAtUtc="2026-10-22T23:59:00Z", selectors=[])
            published = dt.datetime.fromisoformat("2026-10-23T02:00:00+02:00")
            path = publish(value, directory, 2, "finished", published)
            self.assertIn("dayPK=20261023/hourPK=00", str(path))
            self.assertEqual(publish(value, directory, 2, "finished", published), path)
            self.assertEqual(len(list(Path(directory).rglob("*.parquet"))), 1)

    def test_success_and_failure_preserve_selectors_and_host(self):
        for fail in (False, True):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "manifest.json"
                @smoke_run("file-capture")
                def test():
                    record(selectors=[dict(domain="file", pids=[42], pathPrefix="/vm/only/")])
                    if fail:
                        raise ValueError("synthetic failure")
                    return 0
                with patch.object(sys, "argv", ["test.py", "--manifest", str(path)]):
                    if fail:
                        with self.assertRaises(ValueError):
                            test()
                    else:
                        test()
                result = json.loads(path.read_text())
                self.assertTrue(result["host"]["hostname"])
                self.assertTrue(result["runId"])
                self.assertEqual(result["status"], "failed" if fail else "passed")
                self.assertEqual(result["selectors"][0]["pids"], [42])
                self.assertTrue(result["completedAtUtc"])


if __name__ == "__main__":
    unittest.main()
