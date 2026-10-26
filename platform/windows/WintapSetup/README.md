# Legacy Visual Studio installer snapshots

`WintapSetup.vdproj` and `wintapv7setup/wintapv7setup.vdproj` are retained historical
installer definitions, not the current .NET 10 release packaging path. They remain
listed in the older Visual Studio solution and contain stale .NET 8 publish paths
and dependency inventories. Do not build or deploy them as a .NET 10 package.

The current release workflow is [`../../../.github/workflows/release.yml`](../../../.github/workflows/release.yml)
and builds [`../../../installer/Wintap.Installer.wixproj`](../../../installer/Wintap.Installer.wixproj).
See [`../../../BUILD_AND_TEST.md`](../../../BUILD_AND_TEST.md) for the current SDK
baseline. Linux package results do not certify a Windows MSI or Windows runtime.
