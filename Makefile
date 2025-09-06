BPF_CLANG ?= clang
BPF_LLVM_STRIP ?= llvm-strip
GO ?= go

BPF_OBJ = internal/ebpf/http_monitor_bpfel.o
BPF_SRC = internal/ebpf/bpf/http_monitor_v3.c

all: build

.PHONY: build
build: $(BPF_OBJ)
	$(GO) build -o http-monitor ./cmd

$(BPF_OBJ): $(BPF_SRC)
	$(BPF_CLANG) -O2 -g -target bpf -D__TARGET_ARCH_x86 -c $(BPF_SRC) -o $(BPF_OBJ)
	$(BPF_LLVM_STRIP) -g $(BPF_OBJ)

.PHONY: clean
clean:
	rm -f $(BPF_OBJ) http-monitor