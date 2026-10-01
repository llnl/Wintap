# Configuration
EBPF_DIR = platform/linux/sensor/ebpf/tracers
DOTNET_PROJ = Lintap.csproj
DOTNET_CONFIG ?= Debug
DOTNET_TFM ?= net8.0
NATIVE_BUILD_ROOT ?= /tmp/lintap-build/$(notdir $(CURDIR))
DOTNET_OUT_DIR ?= bin/$(DOTNET_CONFIG)/$(DOTNET_TFM)
LINTAP_DLL ?= $(DOTNET_OUT_DIR)/Lintap.dll
MCP_EXE ?= $(DOTNET_OUT_DIR)/mcp/wintap_mcp_server
WINTAP_DATA_ROOT ?= /tmp/lintap-data
WINTAP_DISABLE_MCP ?= true
WINTAP_DISABLE_DUCKDB_UI ?= true
WINTAP_DISABLE_ETL ?= false
WINTAP_DISABLE_SENSORS ?= false
WINTAP_DISABLE_ESPER_ENUM_CAST ?= false
WINTAP_ENABLE_DIRECT_PARQUET ?= false
WINTAP_DIRECT_PARQUET_FLUSH_SECONDS ?= 15
WINTAP_SKIP_PROCESS_RESOLVE ?= false
WINTAP_SKIP_PARENT_PROCESS_RESOLVE ?= false
WINTAP_SKIP_PROCESS_REGISTER ?= false
WINTAP_SKIP_ESPER_SEND ?= false

# Per-sensor flags are explicit overrides. Do not default them here; otherwise
# make run exports false values that mask ConfigRoot's sensor defaults.
SENSOR_ENV := \
  $(if $(WINTAP_ENABLE_EXECVE_SENSOR),WINTAP_ENABLE_EXECVE_SENSOR=$(WINTAP_ENABLE_EXECVE_SENSOR)) \
  $(if $(WINTAP_ENABLE_CLONE_SENSOR),WINTAP_ENABLE_CLONE_SENSOR=$(WINTAP_ENABLE_CLONE_SENSOR)) \
  $(if $(WINTAP_ENABLE_EXIT_SENSOR),WINTAP_ENABLE_EXIT_SENSOR=$(WINTAP_ENABLE_EXIT_SENSOR)) \
  $(if $(WINTAP_ENABLE_NETWORK_SENSOR),WINTAP_ENABLE_NETWORK_SENSOR=$(WINTAP_ENABLE_NETWORK_SENSOR)) \
  $(if $(WINTAP_ENABLE_FILEOPS_SENSOR),WINTAP_ENABLE_FILEOPS_SENSOR=$(WINTAP_ENABLE_FILEOPS_SENSOR)) \
  $(if $(WINTAP_ENABLE_SELINUX_SENSOR),WINTAP_ENABLE_SELINUX_SENSOR=$(WINTAP_ENABLE_SELINUX_SENSOR)) \
  $(if $(WINTAP_ENABLE_PROCESS_RUNDOWN_SENSOR),WINTAP_ENABLE_PROCESS_RUNDOWN_SENSOR=$(WINTAP_ENABLE_PROCESS_RUNDOWN_SENSOR))

.PHONY: all clean build_ebpf build_dotnet run run-host-only run-mcp run-env test_ebpf test_all

# 1. The "Build Everything" target
all: build_ebpf build_dotnet

# 2. Build the eBPF components
build_ebpf:
	@echo "--- Building eBPF Tracers ---"
	$(MAKE) -C $(EBPF_DIR) all

# Optional additional flags for dotnet build (e.g. -p:UseAppHost=false)
## Comma/pipe-separated list of filesystem types that indicate a shared/host-mounted
## filesystem where memory-mapped file operations used by the .NET SDK may fail.
## Override if your environment uses different mount types.
SHARED_MOUNT_TYPES ?= 9p|virtiofs|vboxsf|fuse|smbfs|cifs|osxfs

# DOTNET_BUILD_FLAGS can be provided by the user/environment. If not set,
# auto-detect whether the current working directory is on a host-shared filesystem
# and disable the apphost creation step to avoid mmap errors.
DOTNET_BUILD_FLAGS ?=

# If DOTNET_BUILD_FLAGS was not provided, compute MOUNT_TYPE at parse time and
# set DOTNET_BUILD_FLAGS accordingly. We convert the pipe-separated
# SHARED_MOUNT_TYPES into a space-separated list for make's filter function.
ifeq ($(DOTNET_BUILD_FLAGS),)
MOUNT_TYPE := $(shell awk -v dir="$(PWD)" 'BEGIN{best="";bestlen=0} {mp=$$2; if(index(dir,mp)==1 && length(mp)>bestlen){bestlen=length(mp); fstype=$$3}} END{print fstype}' /proc/mounts 2>/dev/null)
ifneq ($(filter $(MOUNT_TYPE),$(subst |, ,$(SHARED_MOUNT_TYPES))),)
$(info Detected filesystem type '$(MOUNT_TYPE)' for $(PWD) — using native build output to avoid mmap and runtime codegen errors)
DOTNET_OUT_DIR := $(NATIVE_BUILD_ROOT)/bin/$(DOTNET_CONFIG)/$(DOTNET_TFM)
DOTNET_BUILD_FLAGS := -p:UseAppHost=false -p:NativeBuildRoot=$(NATIVE_BUILD_ROOT)/ -p:OutputPath=$(DOTNET_OUT_DIR)/
LINTAP_DLL := $(DOTNET_OUT_DIR)/Lintap.dll
MCP_EXE := $(DOTNET_OUT_DIR)/mcp/wintap_mcp_server
DISABLE_APPHOST := true
export DISABLE_APPHOST
endif
endif

# 3. Build the .NET components
build_dotnet:
	@echo "--- Building .NET Project ---"
	DISABLE_MCP=$(WINTAP_DISABLE_MCP) dotnet build $(DOTNET_PROJ) $(DOTNET_BUILD_FLAGS)

# 4. Run the already-built .NET application without invoking dotnet run's build/apphost path.
run: build_dotnet
	@echo "--- Running Lintap ---"
	WINTAP_DATA_ROOT=$(WINTAP_DATA_ROOT) WINTAP_DISABLE_MCP=$(WINTAP_DISABLE_MCP) WINTAP_DISABLE_DUCKDB_UI=$(WINTAP_DISABLE_DUCKDB_UI) WINTAP_DISABLE_ETL=$(WINTAP_DISABLE_ETL) WINTAP_DISABLE_SENSORS=$(WINTAP_DISABLE_SENSORS) WINTAP_DISABLE_ESPER_ENUM_CAST=$(WINTAP_DISABLE_ESPER_ENUM_CAST) WINTAP_ENABLE_DIRECT_PARQUET=$(WINTAP_ENABLE_DIRECT_PARQUET) WINTAP_DIRECT_PARQUET_FLUSH_SECONDS=$(WINTAP_DIRECT_PARQUET_FLUSH_SECONDS) WINTAP_SKIP_PROCESS_RESOLVE=$(WINTAP_SKIP_PROCESS_RESOLVE) WINTAP_SKIP_PARENT_PROCESS_RESOLVE=$(WINTAP_SKIP_PARENT_PROCESS_RESOLVE) WINTAP_SKIP_PROCESS_REGISTER=$(WINTAP_SKIP_PROCESS_REGISTER) WINTAP_SKIP_ESPER_SEND=$(WINTAP_SKIP_ESPER_SEND) $(SENSOR_ENV) dotnet $(LINTAP_DLL)

# Run the web host with optional native-heavy startup paths disabled. Use this to
# distinguish host/runtime problems from ETL, DuckDB UI, MCP, and eBPF sensor issues.
run-host-only: build_dotnet
	@echo "--- Running Lintap host only ---"
	WINTAP_DATA_ROOT=$(WINTAP_DATA_ROOT) WINTAP_DISABLE_MCP=true WINTAP_DISABLE_DUCKDB_UI=true WINTAP_DISABLE_ETL=true WINTAP_DISABLE_SENSORS=true dotnet $(LINTAP_DLL)

# Run the MCP server directly. This is useful for isolating native crashes in the
# single-file MCP executable (DuckDB.NET/native runtime extraction, RID issues, etc.).
run-mcp: build_dotnet
	@echo "--- Running MCP server directly ---"
	WINTAP_DATA_ROOT=$(WINTAP_DATA_ROOT) $(MCP_EXE)

# Print runtime paths and binary metadata for Fedora/VM troubleshooting.
run-env: build_dotnet
	@echo "--- Runtime environment ---"
	@echo "PWD=$$(pwd)"
	@echo "WINTAP_DATA_ROOT=$(WINTAP_DATA_ROOT)"
	@echo "WINTAP_DISABLE_MCP=$(WINTAP_DISABLE_MCP)"
	@echo "WINTAP_DISABLE_DUCKDB_UI=$(WINTAP_DISABLE_DUCKDB_UI)"
	@echo "WINTAP_DISABLE_ETL=$(WINTAP_DISABLE_ETL)"
	@echo "WINTAP_DISABLE_SENSORS=$(WINTAP_DISABLE_SENSORS)"
	@echo "WINTAP_DISABLE_ESPER_ENUM_CAST=$(WINTAP_DISABLE_ESPER_ENUM_CAST)"
	@echo "WINTAP_ENABLE_DIRECT_PARQUET=$(WINTAP_ENABLE_DIRECT_PARQUET)"
	@echo "WINTAP_DIRECT_PARQUET_FLUSH_SECONDS=$(WINTAP_DIRECT_PARQUET_FLUSH_SECONDS)"
	@echo "WINTAP_SKIP_PROCESS_RESOLVE=$(WINTAP_SKIP_PROCESS_RESOLVE)"
	@echo "WINTAP_SKIP_PARENT_PROCESS_RESOLVE=$(WINTAP_SKIP_PARENT_PROCESS_RESOLVE)"
	@echo "WINTAP_SKIP_PROCESS_REGISTER=$(WINTAP_SKIP_PROCESS_REGISTER)"
	@echo "WINTAP_SKIP_ESPER_SEND=$(WINTAP_SKIP_ESPER_SEND)"
	@echo "SENSOR_ENV=$(SENSOR_ENV)"
	@echo "NATIVE_BUILD_ROOT=$(NATIVE_BUILD_ROOT)"
	@echo "DOTNET_BUILD_FLAGS=$(DOTNET_BUILD_FLAGS)"
	@echo "LINTAP_DLL=$(LINTAP_DLL)"
	@echo "MCP_EXE=$(MCP_EXE)"
	@file "$(MCP_EXE)" || true
	@ldd "$(MCP_EXE)" || true

# 5. Run eBPF tests
test_ebpf:
	@echo "--- Running eBPF Tests ---"
	$(MAKE) -C $(EBPF_DIR) test

# 6. Run everything (eBPF tests + full build)
test_all: test_ebpf build_ebpf build_dotnet

# 7. Clean everything
clean:
	@echo "--- Cleaning eBPF ---"
	$(MAKE) -C $(EBPF_DIR) clean
	@echo "--- Cleaning .NET (with forced restore) ---"
	# We run restore first to satisfy the SDK's dependency check, 
	# then we clean.
	dotnet restore $(DOTNET_PROJ) || true
	dotnet clean $(DOTNET_PROJ)
