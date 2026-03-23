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

# Compiler flags for eBPF programs
# -g: Include debug info (required for BTF)
# -O2: Optimization level (required for some BPF features)
# -target bpf: Generate BPF bytecode
# -D__TARGET_ARCH_$(ARCH): Define target architecture for CO-RE
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)

# Compiler flags for user-space program
# -Wall -Wextra: Enable warnings
# -g: Debug info for debugging
USER_CFLAGS := -Wall -Wextra -g $(INCLUDES)

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

# Default target: build everything
.PHONY: all
all: $(USER_BINS)

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