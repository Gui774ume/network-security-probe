SHELL=/bin/bash -o pipefail
SRC_DIR?=src
GO_SRC_DIR?=go_src
LINUX_HEADERS=$(shell rpm -q kernel-devel --last | head -n 1 | awk -F'kernel-devel-' '{print "/usr/src/kernels/"$$2}' | cut -d " " -f 1)

build:
	mkdir -p /${SRC_DIR}/bin
	clang -D__KERNEL__ -D__ASM_SYSREG_H \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wunused \
		-Wall \
		-Werror \
		-O2 -emit-llvm -c main.c \
		$(foreach path,$(LINUX_HEADERS), -I $(path)/arch/x86/include -I $(path)/arch/x86/include/generated -I $(path)/include -I $(path)/include/generated/uapi -I $(path)/arch/x86/include/uapi -I $(path)/include/uapi) \
		-o - | llc -march=bpf -filetype=obj -o "/${SRC_DIR}/bin/probe.o"
	go-bindata -pkg ebpf -prefix "ebpf/bin" -modtime 1 -o "/${GO_SRC_DIR}/probe.go" "/${SRC_DIR}/bin"
