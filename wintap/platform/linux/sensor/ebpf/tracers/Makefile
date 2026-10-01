# Output files
# CO-RE objects require kernel BTF/vmlinux.h and provide richer kernel-internal context.
CORE_OBJS = execve_tracer.bpf.o exit_tracer.bpf.o network_ops_tracer.bpf.o file_ops_tracer.bpf.o selinux_tracer.bpf.o

# Tracepoint-only objects avoid vmlinux.h and are the portability fallback tier.
TRACEPOINT_OBJS = clone_tracer.bpf.o openat_tracer.bpf.o execve_tracepoint.bpf.o exit_tracepoint.bpf.o network_tracepoint.bpf.o file_ops_tracepoint.bpf.o

# Always-clean set (avoid stale CO-RE objs when building tracepoint-only).
ALL_OBJS = $(TRACEPOINT_OBJS) $(CORE_OBJS)
KERNEL_RELEASE := $(shell uname -r)
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux

# Auto-detect architecture
ARCH := $(shell uname -m)
ifeq ($(ARCH),aarch64)
	TARGET_ARCH := arm64
else ifeq ($(ARCH),x86_64)
	TARGET_ARCH := x86
else ifeq ($(ARCH),armv7l)
	TARGET_ARCH := arm
else ifeq ($(ARCH),ppc64le)
	TARGET_ARCH := powerpc
else ifeq ($(ARCH),s390x)
	TARGET_ARCH := s390
else
	TARGET_ARCH := $(ARCH)
endif

BPF_BUILD_DIR ?= .build/$(ARCH)-$(KERNEL_RELEASE)
VMLINUX = $(BPF_BUILD_DIR)/vmlinux.h
BTF_AVAILABLE := $(shell test -r "$(VMLINUX_BTF)" && echo yes || echo no)
ifeq ($(BTF_AVAILABLE),yes)
OBJS = $(TRACEPOINT_OBJS) $(CORE_OBJS)
else
OBJS = $(TRACEPOINT_OBJS)
endif

# Only generate vmlinux.h when BTF is available/readable. This matters for
# cross-build packaging where we intentionally disable BTF to build tracepoint
# fallback objects without requiring a target-arch BTF.
VMLINUX_DEP :=
ifeq ($(BTF_AVAILABLE),yes)
VMLINUX_DEP := $(VMLINUX)
endif

.PHONY: all clean test preflight

all: preflight $(VMLINUX_DEP) $(OBJS)

preflight:
	@echo "--- eBPF build preflight ---"
	@echo "kernel=$$(uname -r) arch=$$(uname -m) target_arch=$(TARGET_ARCH)"
	@command -v clang >/dev/null || { echo "ERROR: clang is required to build eBPF objects."; exit 1; }
	@if test "$(BTF_AVAILABLE)" = "yes"; then \
		command -v bpftool >/dev/null || { echo "ERROR: bpftool is required to generate vmlinux.h from BTF."; exit 1; }; \
		echo "btf=$(VMLINUX_BTF)"; \
	else \
		echo "WARN: $(VMLINUX_BTF) is missing or unreadable; building tracepoint fallback objects only."; \
	fi

# CO-RE objects compile against generated vmlinux.h.
$(CORE_OBJS): %.bpf.o: %.bpf.c $(VMLINUX)
	clang -g -O2 -target bpf -D__TARGET_ARCH_$(TARGET_ARCH) \
	-I$(BPF_BUILD_DIR) -I/usr/include/bpf -c $< -o $@
	@echo "Compiled CO-RE $< for architecture: $(TARGET_ARCH)"

# Tracepoint fallback objects do not require BTF/vmlinux.h.
$(TRACEPOINT_OBJS): %.bpf.o: %.bpf.c
	clang -g -O2 -target bpf -D__TARGET_ARCH_$(TARGET_ARCH) \
	-I/usr/include/bpf -c $< -o $@
	@echo "Compiled tracepoint fallback $< for architecture: $(TARGET_ARCH)"

$(VMLINUX):
	@mkdir -p $(BPF_BUILD_DIR)
	bpftool btf dump file $(VMLINUX_BTF) format c > $(VMLINUX)
	@echo "Generated $(VMLINUX) from $(VMLINUX_BTF)"

# Placeholder for your test logic
test: all
	@echo "Running eBPF tests..."
	# Add your actual test command here, e.g.:
	# ./test_runner --objs $(OBJS)
	@echo "eBPF tests passed!"

clean:
	rm -f $(ALL_OBJS)
	rm -rf .build
