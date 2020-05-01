FROM fedora:26

ENV GOPATH /go

RUN dnf update -y vim-minimal && \
	dnf install -y llvm clang kernel-devel make binutils vim-common golang go-bindata ShellCheck git file

RUN mkdir -p /src /go_src
