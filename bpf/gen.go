package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type bigkey_log  -target amd64 Agent ./pktlatency.bpf.c -- -I./ -I$OUTPUT -I../libbpf/include/uapi -I../vmlinux/x86/
