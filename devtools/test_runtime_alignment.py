"""Source-wide .NET target and active-default drift gates (no host capture)."""
import json
from pathlib import Path
import subprocess
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]


class RuntimeAlignmentTests(unittest.TestCase):
    def test_all_tracked_csharp_targets_are_net10(self):
        projects = subprocess.check_output(
            ["git", "ls-files", "*.csproj"], cwd=ROOT, text=True).splitlines()
        self.assertEqual(len(projects), 13)
        for name in projects:
            with self.subTest(project=name):
                project = ET.parse(ROOT / name)
                targets = project.findall(".//TargetFramework")
                if not targets:
                    imports = project.findall("Import")
                    self.assertTrue(any(item.get("Project") == "Wintap.Common.props" for item in imports))
                    targets = ET.parse((ROOT / name).parent / "Wintap.Common.props").findall(".//TargetFramework")
                self.assertTrue(targets)
                for target in targets:
                    self.assertRegex(target.text, r"^net10\.0(?:-windows[\d.]*)?$")
                for item in project.findall(".//ProjectReference"):
                    reference = item.get("Include").replace("\\", "/")
                    self.assertTrue((ROOT / name).parent.joinpath(reference).is_file(), reference)

    def test_sdk_baseline_is_exact_qualified_version(self):
        sdk = json.loads((ROOT / "global.json").read_text())["sdk"]
        self.assertEqual(sdk["version"], "10.0.402")
        self.assertFalse(sdk["allowPrerelease"])

    def test_redirected_builds_exclude_old_generated_sources(self):
        props = ET.parse(ROOT / "Directory.Build.props")
        exclusions = props.findall(".//DefaultItemExcludes")
        self.assertTrue(any("NativeBuildRoot" in item.get("Condition", "") and
                            "bin\\**;obj\\**" in item.text for item in exclusions))

    def test_sample_windows_copy_does_not_run_on_linux(self):
        project = ET.parse(ROOT / "shared/samples/SimpleEventPlugin/SimpleEventPlugin.csproj")
        condition = project.find("Target[@Name='PostBuild']").get("Condition")
        self.assertIn("Windows_NT", condition)
        self.assertIn("*Undefined*", condition)

    def test_makefile_and_active_tools_have_no_net8_defaults(self):
        names = ["wintap/Makefile", "diagnostics/process-smoke-test/Program.cs",
                 "diagnostics/nesper-repro/README.md", "devtools/README.md",
                 "devtools/collect-linux-baseline.sh", "devtools/network_tcpdump_validation.py",
                 "devtools/file_capture_smoke_test.py", "README.md", "CLAUDE.md",
                 "documentation/Linux Deployment Guide.md"]
        for name in names:
            with self.subTest(path=name):
                self.assertNotRegex((ROOT / name).read_text(),
                                    r"net8\.0|(?:dotnet|aspnetcore)-(?:sdk|runtime)-8\.0|\.NET 8")
        self.assertIn("DOTNET_TFM ?= net10.0", (ROOT / "wintap/Makefile").read_text())

    def test_legacy_installers_are_explicitly_not_release_path(self):
        note = (ROOT / "platform/windows/WintapSetup/README.md").read_text()
        self.assertIn("historical", note)
        self.assertIn("Do not build or deploy", note)
        self.assertIn("installer/Wintap.Installer.wixproj", note)
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertIn("dotnet build installer/Wintap.Installer.wixproj", workflow)
        self.assertNotIn(".vdproj", workflow)


if __name__ == "__main__":
    unittest.main()
