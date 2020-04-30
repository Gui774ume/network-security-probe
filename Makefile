PWD=$(shell pwd)
UID=$(shell id -u)
EBPF_DOCKER_FILE?=ebpf/Dockerfile
EBPF_DOCKER_IMAGE?=network-security-probe-builder
PONG_DOCKER_FILE?=cmd/pong/Dockerfile
PONG_DOCKER_IMAGE?=pong
PING_DOCKER_FILE?=cmd/ping/Dockerfile
PING_DOCKER_IMAGE?=ping
UTILS_DOCKER_FILE?=cmd/attacker/Dockerfile
UTILS_DOCKER_IMAGE?=attacker

all: build run

build: build-ebpf build-nsp

insert-veth:
	sudo modprobe veth

build-ebpf:
	mkdir -p ebpf/bin
	clang -D__KERNEL__ -D__ASM_SYSREG_H \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wunused \
		-Wall \
		-Werror \
		-I/lib/modules/$$(uname -r)/build/include \
		-I/lib/modules/$$(uname -r)/build/include/uapi \
		-I/lib/modules/$$(uname -r)/build/include/generated/uapi \
		-I/lib/modules/$$(uname -r)/build/arch/x86/include \
		-I/lib/modules/$$(uname -r)/build/arch/x86/include/uapi \
		-I/lib/modules/$$(uname -r)/build/arch/x86/include/generated \
		-O2 -emit-llvm \
		ebpf/main.c \
		-c -o - | llc -march=bpf -filetype=obj -o ebpf/bin/probe.o
	go-bindata -pkg probe -prefix "ebpf/bin" -modtime 1 -o "pkg/probe/probe.go" "ebpf/bin"

ci-build-image:
	docker build -t $(EBPF_DOCKER_IMAGE) -f $(EBPF_DOCKER_FILE) .

ci-build-ebpf:
	docker run --rm \
		-v $(PWD)/ebpf:/src \
		-v $(PWD)/pkg/ebpf:/go_src \
		--workdir=/src \
		$(EBPF_DOCKER_IMAGE) \
		make -f ebpf.mk build
	sudo chown -R $(UID):$(UID) ebpf

build-nsp:
	go build -mod vendor -o bin/network-security-probe cmd/nsp/main.go

demo: ping pong attacker

ping:
	env GOOS=linux GOARCH=amd64 go build -mod vendor -o bin/ping cmd/ping/main.go
	env GOOS=linux GOARCH=amd64 go build -mod vendor -o bin/nspbench cmd/nspbench/main.go
	docker build -t $(PING_DOCKER_IMAGE) -f $(PING_DOCKER_FILE) .

pong:
	env GOOS=linux GOARCH=amd64 go build -mod vendor -o bin/pong cmd/pong/main.go
	docker build -t $(PONG_DOCKER_IMAGE) -f $(PONG_DOCKER_FILE) .

attacker:
	docker build -t $(UTILS_DOCKER_IMAGE) -f $(UTILS_DOCKER_FILE) .

run:
	sudo bin/network-security-probe --kubeconfig ~/.kube/config

run_agent:
	docker-compose up
