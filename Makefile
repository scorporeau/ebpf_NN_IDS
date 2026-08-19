# Makefile for libbpf-based eBPF project
# Handles compilation of eBPF programs, skeleton generation, and user-space app

# Compiler settings
# CLANG is used for eBPF programs (required for BPF target)
CLANG := clang

# CC is used for user-space programs (can be gcc or clang)
CC := gcc

# Target architecture - detect automatically
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Include paths for headers
INCLUDES := -Iinclude -Ibuild

# Build configuration for optional features.
# Default build: no NOKTIME, no SILENT.
# `make noktime`: enables both NOKTIME and SILENT automatically.
NOKTIME ?= 0
SILENT ?= 0
NET_INTERFACE ?= enx6c0b5ef61e49

# Compiler flags for eBPF programs
# -g: Include debug info (required for BTF)
# -O2: Optimization level (required for some BPF features)
# -target bpf: Generate BPF bytecode
# -D__TARGET_ARCH_$(ARCH): Define target architecture for CO-RE
# Optional defines are injected here so build mode is controlled centrally.
BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -DNET_INTERFACE=\"$(NET_INTERFACE)\" $(if $(filter 1,$(SILENT)),-DSILENT,) $(if $(filter 1,$(NOKTIME)),-DNOKTIME,)

# Compiler flags for user-space program
# -Wall -Wextra: Enable warnings
# -g: Debug info for debugging
USER_CFLAGS = -Wall -Wextra -g -DNET_INTERFACE=\"$(NET_INTERFACE)\" $(if $(filter 1,$(SILENT)),-DSILENT,) $(if $(filter 1,$(NOKTIME)),-DNOKTIME,) $(INCLUDES)

# Libraries for user-space program
# -lbpf: libbpf library
# -lelf: Required by libbpf
# -lz: Compression library (required by libbpf)
USER_LIBS := -lbpf -lelf -lz

# Output directories and files
BUILD_DIR := build
SRC_DIR := src

# Find all BPF and user-space source files
BPF_SOURCES := $(wildcard $(SRC_DIR)/*.bpf.c)
BPF_OBJECTS := $(patsubst $(SRC_DIR)/%.bpf.c,$(BUILD_DIR)/%.bpf.o,$(BPF_SOURCES))
SKELETONS := $(patsubst $(SRC_DIR)/%.bpf.c,$(BUILD_DIR)/%.skel.h,$(BPF_SOURCES))

USER_SOURCES := $(wildcard $(SRC_DIR)/*.usr.c)
USER_BINS := $(patsubst $(SRC_DIR)/%.usr.c,$(BUILD_DIR)/%,$(USER_SOURCES))

# Keep generated .o and .skel.h files after a build.
# GNU make would otherwise treat them as intermediate and delete them.
.SECONDARY: $(BPF_OBJECTS) $(SKELETONS)

# Default target: build everything without NOKTIME
.PHONY: all noktime
all: $(USER_BINS)

# Build the same project with NOKTIME enabled.
# Noktime implies silent mode to avoid ring-buffer traffic in that mode.
noktime: NOKTIME := 1
noktime: SILENT := 1
noktime: all

# Create build directory if it doesn't exist
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Generate vmlinux.h from kernel BTF
# This only needs to be done once per kernel version
$(BUILD_DIR)/vmlinux.h: | $(BUILD_DIR)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# Compile eBPF programs to object files
# Pattern rule: compile any *.bpf.c to *.bpf.o
$(BUILD_DIR)/%.bpf.o: $(SRC_DIR)/%.bpf.c $(BUILD_DIR)/vmlinux.h | $(BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) $(INCLUDES) -I$(BUILD_DIR) \
		-c $< -o $@

# Generate skeleton headers from BPF object files
# Pattern rule: generate *.skel.h from *.bpf.o
$(BUILD_DIR)/%.skel.h: $(BUILD_DIR)/%.bpf.o
	bpftool gen skeleton $< > $@

# Compile user-space programs
# Pattern rule: compile any *.usr.c to a binary
# Each user program depends on all generated skeleton headers
$(BUILD_DIR)/%: $(SRC_DIR)/%.usr.c $(SKELETONS) | $(BUILD_DIR)
	$(CC) $(USER_CFLAGS) -I$(BUILD_DIR) \
		$< -o $@ $(USER_LIBS)

# Clean build artifacts
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)

# Generate compile_commands.json for IDE support
.PHONY: compile_commands
compile_commands:
	bear -- make clean all

# Install to /usr/local/bin (requires root)
.PHONY: install
install: $(USER_BINS)
	$(foreach bin,$(USER_BINS),install -m 755 $(bin) /usr/local/bin/;)

# Help target
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  all     - Build everything (default)"
	@echo "  clean   - Remove build artifacts"
	@echo "  install - Install binary to /usr/local/bin"
	@echo "  help    - Show this help message"