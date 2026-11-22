using System;
using System.IO;
using System.Reflection;
using gov.llnl.wintap.platform.linux.collect;
using Xunit;

namespace Lintap.Tests
{
    [Trait("Category", "sfx-01")]
    [Trait("TestKind", "unit")]
    [Trait("Execution", "synthetic")]
    public class ExecutableEvidenceTests
    {
        private const string Alias = "/proc/2147483647/exe";

        [Theory]
        [InlineData("missing")]
        [InlineData("denied")]
        [InlineData("exit-race")]
        [InlineData("not-link")]
        [InlineData("empty")]
        public void UnavailableLinkNeverBecomesExecutableEvidence(string failure)
        {
            string ReadLink(string path)
            {
                switch (failure)
                {
                    case "missing": throw new FileNotFoundException();
                    case "denied": throw new UnauthorizedAccessException();
                    case "exit-race": throw new IOException();
                    case "empty": return "";
                    default: return null;
                }
            }

            Assert.Null(ProcessSensorHelper.ResolveExecutablePath(Alias, ReadLink));
            var info = new ProcReader.ProcessInfo
            {
                ExecutablePath = Alias, Name = "ProcComm", CommandLine = "not-path-evidence --synthetic"
            };
            var exec = ExecveSensor.SelectExecutableMetadata(Alias, "EventComm", info, ReadLink);
            Assert.Equal(("unknown-1", "EventComm"), exec);
            var clone = CloneSensor.SelectExecutableMetadata(info, default, "ParentComm", ReadLink);
            Assert.Equal(("unknown", "ProcComm"), clone);
            info.Name = "";
            exec = ExecveSensor.SelectExecutableMetadata(Alias, "", info, ReadLink);
            Assert.Equal(("unknown-1", "unknown"), exec);
            clone = CloneSensor.SelectExecutableMetadata(info, default, "", ReadLink);
            Assert.Equal(("unknown", "unknown"), clone);
        }

        [Theory]
        [InlineData("/opt/synthetic/My Worker", "My Worker")]
        [InlineData("/opt/synthetic/exe", "exe")]
        [InlineData("/opt/synthetic/Worker (deleted)", "Worker")]
        public void ExecAndCloneUseResolvedTargetsWithoutRequiringTargetExistence(string target, string name)
        {
            string ReadLink(string path) => target;
            var child = new ProcReader.ProcessInfo { ExecutablePath = Alias, Name = "Comm" };
            Assert.Equal((target, name), ExecveSensor.SelectExecutableMetadata(Alias, "Comm", child, ReadLink));
            Assert.Equal((target, name), CloneSensor.SelectExecutableMetadata(child, default, "ParentComm", ReadLink));
        }

        [Theory]
        [InlineData("/proc/self/exe")]
        [InlineData("/proc/2147483647/task/2147483646/exe")]
        [InlineData("relative-target")]
        [InlineData(null)]
        [InlineData(" ")]
        public void ReadlinkRejectsUnresolvedAliasesAndInvalidTargets(string target)
        {
            Assert.Null(ProcessSensorHelper.ReadExecutableLink(Alias, path => target));
        }

        [Fact]
        public void ExecFallsBackToProcPathThenProcCommWithoutParsingCommandLine()
        {
            var info = new ProcReader.ProcessInfo
            {
                ExecutablePath = "/opt/synthetic/ProcImage", Name = "ProcComm", CommandLine = "fake-command --synthetic"
            };
            Assert.Equal((info.ExecutablePath, "ProcImage"), ExecveSensor.SelectExecutableMetadata(Alias, "EventComm", info, path => null));
            Assert.Equal(("/opt/synthetic/EventImage", "EventImage"), ExecveSensor.SelectExecutableMetadata("/opt/synthetic/EventImage", "EventComm", info));
            info.ExecutablePath = "";
            Assert.Equal(("unknown-1", "ProcComm"), ExecveSensor.SelectExecutableMetadata("", "", info));
        }

        [Fact]
        public void CloneRetainsChildThenParentExecutablePreference()
        {
            var child = new ProcReader.ProcessInfo { ExecutablePath = "/opt/synthetic/ChildImage", Name = "ChildComm" };
            var parent = new ProcReader.ProcessInfo { ExecutablePath = "/opt/synthetic/ParentImage", Name = "ParentProcComm" };
            Assert.Equal((child.ExecutablePath, "ChildImage"), CloneSensor.SelectExecutableMetadata(child, parent, "ParentEventComm"));
            child.ExecutablePath = Alias;
            Assert.Equal((parent.ExecutablePath, "ParentImage"), CloneSensor.SelectExecutableMetadata(child, parent, "ParentEventComm", path => null));
            parent.ExecutablePath = "";
            child.Name = "";
            Assert.Equal(("unknown", "ParentEventComm"), CloneSensor.SelectExecutableMetadata(child, parent, "ParentEventComm", path => null));
            Assert.Equal(("unknown", "ParentProcComm"), CloneSensor.SelectExecutableMetadata(child, parent, "", path => null));
        }

        [Fact]
        public void NonProcExecutableNamedExeIsNotTreatedAsAnAlias()
        {
            string path = "/opt/synthetic/exe";
            Assert.Equal(path, ProcessSensorHelper.ResolveExecutablePath(path, _ => throw new InvalidOperationException("Must not read a non-proc path")));
        }

        [Theory]
        [InlineData("linked")]
        [InlineData("deleted")]
        [InlineData("ordinary-file")]
        [InlineData("missing")]
        public void ProcReaderReadsOnlyLinkEvidenceAndRundownUsesIt(string kind)
        {
            using var directory = new SyntheticDirectory();
            string link = Path.Combine(directory.Path, "exe");
            string target = Path.Combine(directory.Path, "My Worker");
            if (kind == "linked")
            {
                File.WriteAllText(target, "synthetic executable placeholder");
                File.CreateSymbolicLink(link, target);
            }
            else if (kind == "deleted")
            {
                target += " (deleted)";
                File.CreateSymbolicLink(link, target);
            }
            else if (kind == "ordinary-file") File.WriteAllText(link, "synthetic non-link");

            var info = new ProcReader.ProcessInfo
            {
                Exists = true, Pid = 2147483647, PPid = 0, Name = "ObservedComm", Username = "",
                StartTimeUtc = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc)
            };
            object[] args = { directory.Path, info };
            typeof(ProcReader).GetMethod("ReadExe", BindingFlags.Static | BindingFlags.NonPublic).Invoke(null, args);
            info = (ProcReader.ProcessInfo)args[1];
            bool hasTarget = kind == "linked" || kind == "deleted";
            Assert.Equal(hasTarget ? target : null, info.ExecutablePath);
            var message = new ProcessRundownSensor().CreateRefreshMessage(info);
            Assert.Equal(hasTarget ? "My Worker" : "ObservedComm", message.Process.Name);
            Assert.Equal(hasTarget ? target : "unknown-5", message.Process.Path);
        }

        [Fact]
        public void MissingProcessHelperCannotReturnItsOwnProcAlias()
        {
            Assert.Null(ProcessSensorHelper.GetExecutablePath(2147483647, Alias));
            Assert.Equal("/opt/synthetic/exe", ProcessSensorHelper.GetExecutablePath(2147483647, "/opt/synthetic/exe"));
        }
    }
}
