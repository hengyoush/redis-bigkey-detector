//go:build ignore

// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "../vmlinux/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h> 
#include <bpf/bpf_endian.h>
#include "pktlatency.h"

const struct bigkey_log *bigkey_log_unused __attribute__((unused));

#define CONN_FD_OFFSET 10 // todo
static __always_inline void get_client_fd(struct client_t* client, u32 *fd) {
	struct connection* p_conn = _U(client, conn);
	if (!p_conn) {
		//bpf_printk("read conn err");
		return ;
	}
	int fd2 = _U(p_conn, fd);
	*fd = fd2;
	
	// void* conn = NULL;
	// int err = bpf_probe_read_user(&conn, sizeof(conn), client + 8);
	// err = bpf_probe_read_user(fd, sizeof(u32), conn+CONN_FD_OFFSET);
	// if (err) {
	// 	//bpf_printk("read fd err: %d", err);
	// }
}
SEC("uprobe//root/workspace/redis-6.2.13/src/redis-server:_addReplyToBufferOrList")
int BPF_UPROBE(addReplyToBufferOrList) {
	size_t len = (size_t)PT_REGS_PARM3(ctx);
	u32 key = 0;
	u64 sum = len;
	u64* reply_bytes = bpf_map_lookup_elem(&reply_bytes_map, &key);
	if (reply_bytes) {
		sum += *reply_bytes;
	}
	if (sum ==213589) {
	//bpf_printk("[addReplyToBufferOrList] sum is: %lld, %lld", sum, bpf_ktime_get_ns());
	}
	bpf_map_update_elem(&reply_bytes_map, &key, &sum, BPF_ANY);
	return BPF_OK;
}

SEC("uprobe//root/workspace/redis-6.2.13/src/redis-server:call")
int BPF_UPROBE(callEntry) {
	u32 key = 0;
	u64* reply_bytes = bpf_map_lookup_elem(&reply_bytes_map, &key);
	if (reply_bytes) {
		//bpf_printk("[callEntry] %lld %lld",*reply_bytes,bpf_ktime_get_ns());
	} else {
		//bpf_printk("[callEntry] %lld",bpf_ktime_get_ns());
	}
	bpf_map_delete_elem(&reply_bytes_map, &key);

	struct client_t* client = PT_REGS_PARM1(ctx);
	if (client) {

	//bpf_printk("111cleint: %x, id: %d\n", client, _U(client,id));
	bpf_map_update_elem(&call_args_map, &key, &client, BPF_ANY);
	}
	return BPF_OK;
}
#define REALCMD_OFFSET 144

struct redisCommand {
	char *declared_name;
};
# define MAX_BYTES 0

SEC("uretprobe//root/workspace/redis-6.2.13/src/redis-server:call")
int BPF_URETPROBE(callReturn) {
	//bpf_printk("[callReturn] %lld",bpf_ktime_get_ns());
	{
		
		u32 key = 0;
		u64* reply_bytes = bpf_map_lookup_elem(&reply_bytes_map, &key);
		if (reply_bytes) {
			//bpf_printk("[callReturn] %lld %lld",*reply_bytes,bpf_ktime_get_ns());
		}
	}
	int err = 0;

	u32 key = 0;
	struct client_t** p_client = bpf_map_lookup_elem(&call_args_map, &key);
	if (!p_client) {
		return BPF_OK;
	}
	struct client_t* client = *p_client;
	//bpf_printk("cleint: %x, id: %d\n", client, _U(client,id));
	u64 *p_bytes = bpf_map_lookup_elem(&reply_bytes_map, &key);
	if (!p_bytes) {
		return BPF_OK;
	}
	u64 bytes = *p_bytes;
	if (bytes > MAX_BYTES) {

		int zero = 0;
		struct bigkey_log* evt = bpf_map_lookup_elem(&bigkey_log_stack_map, &zero);
		if (!evt) {
			return BPF_OK;
		}
		evt->arg_len = 0;
		evt->fd = 0;
		// record cmd name cmd args and client ip
		// 1. client ip
		u32 fd = 0;
		get_client_fd(client, &fd);
		evt->fd = fd;
		//bpf_printk("fd %d\n",fd);

		// 2. cmd args
		struct robj **argv = _U(client, original_argv) ? _U(client, original_argv) : _U(client, argv);
		//bpf_printk("argv %llx\n",argv);
    	uint8_t argc = _U(client, original_argv) ? _U(client, original_argc) : _U(client, argc);
		argc = argc > MAX_ARGS_LEN ? MAX_ARGS_LEN:argc;
		//bpf_printk("argc %d\n",argc);
		for (uint8_t idx = 0; idx < argc; idx++) {
			struct bigkey_arg _arg = {0};//evt->bigkey_args[idx]
			// struct bigkey_arg *arg = &_arg;
			struct bigkey_arg *arg =&evt->bigkey_args[idx];
			arg->type = INVALID;

			struct robj* each = NULL;
			bpf_probe_read_user(&each, sizeof(struct robj*), &argv[idx]); // 这里可能出错
			//bpf_printk("robj[%d]: %llx \n", idx,each );

			u32 x = 0;
			bpf_probe_read_user(&x, sizeof(x) , each);
			//bpf_printk("x: %x %d %d \n", x, x & 0xF, (x >> 4) & 0xF);

			unsigned type = x & 0xF;
			unsigned encoding = (x >> 4) & 0xF;
			// 获取 len + buf, 并且读取一部分
			if (type == OBJ_STRING) {
				// 只处理string
				sds s = _U(each, ptr);
				char* buf = s;
				size_t len = sdslen(s);
				len = len <= MAX_STRING_LEN ? len:MAX_STRING_LEN;
				arg->trucated = len <= MAX_STRING_LEN;
				arg->len = len;
				arg->type = OBJ_STRING;
				bpf_probe_read(arg->arg0, MAX_STRING_LEN, buf);

				//bpf_printk("MYDEBUG type:%d, encodeding: %d, sdslen: %d\n", arg->type, 0, len);
			}

			evt->arg_len++;
			bpf_probe_read_kernel(&evt->bigkey_args[idx], sizeof(struct bigkey_arg), arg);
		}
		bpf_perf_event_output(ctx, &bigkey_event_map, BPF_F_CURRENT_CPU, evt, sizeof(struct bigkey_log));
	}
	return BPF_OK;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";