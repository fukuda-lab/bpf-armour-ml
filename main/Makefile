CLANG  := clang
CC     := gcc
BPFTOOL ?= bpftool


ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

SRC_BPF  := bpf-guard.c

BPF_OBJ  := bpf-guard.o

CFLAGS_BPF  := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)
LDFLAGS     := -lbpf -lelf -lz

.PHONY: all clean

all: $(OUTPUT) $(BPF_OBJ) $(APP_BIN)

$(BPF_OBJ): $(SRC_BPF)
	$(CLANG) $(CFLAGS_BPF) -c $(SRC_BPF) -o $@

clean:
	rm -rf $(OUTPUT)