CLANG   := clang
CC      := gcc
BPFTOOL ?= bpftool

ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

# --- eBPF Program Variables ---
SRC_BPF     := bpf-guard.c
BPF_OBJ     := bpf-guard.o
CFLAGS_BPF  := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)

# --- User-Space Program Variables ---
LIBBPF_INCLUDE := ../lib/libbpf/src
LIBBPF_LIB     := ../lib/libbpf/src

SRC_APP     := map-reader.c
APP_BIN     := map-reader
CFLAGS_APP  := -g -O2 -Wall -I$(LIBBPF_INCLUDE)
LDFLAGS     := -L$(LIBBPF_LIB) -Wl,-rpath=$(LIBBPF_LIB)
LDLIBS      := -lbpf -lelf -lz

.PHONY: all clean

# The default 'all' target builds both the kernel BPF object and the user-space app
all: $(BPF_OBJ) $(APP_BIN)

# Rule to compile the eBPF program using clang
$(BPF_OBJ): $(SRC_BPF)
	$(CLANG) $(CFLAGS_BPF) -c $(SRC_BPF) -o $@

# Rule to compile the user-space map reader using gcc
$(APP_BIN): $(SRC_APP)
	$(CC) $(CFLAGS_APP) $(SRC_APP) -o $@ $(LDFLAGS) $(LDLIBS)

# Rule to clean up compiled files
clean:
	rm -f $(BPF_OBJ) $(APP_BIN)