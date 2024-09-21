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
	// size_t len = (size_t)PT_REGS_PARM3(ctx);
	// u32 key = 0;
	// u64 sum = len;
	// u64* reply_bytes = bpf_map_lookup_elem(&reply_bytes_map, &key);
	// if (reply_bytes) {
	// 	sum += *reply_bytes;
	// }
	// if (sum ==213589) {
	// //bpf_printk("[addReplyToBufferOrList] sum is: %lld, %lld", sum, bpf_ktime_get_ns());
	// }
	// bpf_map_update_elem(&reply_bytes_map, &key, &sum, BPF_ANY);
	return BPF_OK;
}
#define BUFPOS_OFFSET 760
#define REPLY_OFFSET 176

static __always_inline void fillPosData(struct client_data_pos* arg, struct client_t* client) {
		int bufpos = 0;
		bpf_probe_read_user(&bufpos, sizeof(bufpos), (void*)client + BUFPOS_OFFSET);
		//bpf_printk("bufpos: %d\n", bufpos);
		arg->buf_bos = bufpos;

		// reply
		struct list *reply;
		bpf_probe_read_user(&reply, sizeof(reply), (void*)client + REPLY_OFFSET);
		//bpf_printk("reply: %llx \n", reply);
		unsigned long listlen = _U(reply, len);
		struct listNode *tail = _U(reply, tail);
		void *lastValue = _U(tail, value);
		int curListIndex, listOffset;
		if (listlen && lastValue) {
			struct clientReplyBlock* block = (struct clientReplyBlock*)lastValue;
			curListIndex =listlen - 1;
			listOffset = _U(block, used);
		} else {
			curListIndex = 0;
			listOffset = 0;
		}
		//bpf_printk("curListIndex: %d listOffset: %d \n", curListIndex, listOffset);
		arg->client = client;
		arg->list_idx = curListIndex;
		arg->list_offset = listOffset;
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
	struct client_data_pos arg = {0};
	if (client) {
		fillPosData(&arg, client);

	//bpf_printk("111cleint: %x, id: %d\n", client, _U(client,id));
		bpf_map_update_elem(&call_args_map, &key, &arg, BPF_ANY);
	}
	return BPF_OK;
}
#define REALCMD_OFFSET 144

struct redisCommand {
	char *declared_name;
};
// #define MAX_BYTES 1048576
#define MAX_BYTES 0

static __always_inline void listRewind(struct list *list, listIter *li) {
    li->next = _U(list, head);
    li->direction = AL_START_HEAD;
}

static __always_inline listNode *listNext(listIter *iter)
{
    listNode *current = iter->next;

    if (current != NULL) {
        if (iter->direction == AL_START_HEAD)
            iter->next = _U(current,next);
        else
            iter->next = _U(current,prev);
    }
    return current;
}
#define MAX_LOOP_NUM 65
SEC("uretprobe//root/workspace/redis-6.2.13/src/redis-server:call")
int BPF_URETPROBE(callReturn) {
	//bpf_printk("[callReturn] %lld",bpf_ktime_get_ns());
	int err = 0;

	u32 key = 0;
	struct client_data_pos *arg = bpf_map_lookup_elem(&call_args_map, &key);
	if (!arg) {
		return BPF_OK;
	}
	struct client_t* client = arg->client;
	//bpf_printk("cleint: %x, id: %d\n", client, _U(client,id));
	u64 bytes = 0;

	struct client_data_pos after = {0};
	fillPosData(&after, client);
	int afterPos = after.buf_bos;
	int afterListIndex = after.list_idx;
	int afterListOffset = after.list_offset;
	bytes += afterPos - arg->buf_bos;
	// if (afterListIndex - arg->list_idx > MAX_LOOP_NUM) {
	// 	bytes += MAX_BYTES + 1;
	// } else 
	if (afterListIndex > arg->list_idx || afterListOffset > arg->list_offset) {
		int loops = 0;
        int i = 0;
        listIter iter;
        listNode *curr;
        clientReplyBlock *o;
		struct list *reply;
		bpf_probe_read_user(&reply, sizeof(reply), (void*)client + REPLY_OFFSET);
        listRewind(reply, &iter);

		for (;loops <= 65 && (curr = listNext(&iter)) != NULL; loops++) {
			// if (bytes > MAX_BYTES) {
			// 	break;
			// }
			size_t written;
			if (i <arg->list_idx) {
                i++;
                continue;
            }
            o = _U(curr, value);
			size_t used = _U(o,used);
            if (used == 0) {
                i++;
                continue;
            }
			 if (i == arg->list_idx) {
                /* Write the potentially incomplete node, which had data from
                 * before the current command started */
                written = used - arg->list_offset;
            } else {
                /* New node */
                written =used;
            }
            bytes += written;
            i++;
		}
	}
	//bpf_printk("bytes: %d \n", bytes);



	if (bytes > MAX_BYTES) {
		int zero = 0;
		struct bigkey_log* evt = bpf_map_lookup_elem(&bigkey_log_stack_map, &zero);
		if (!evt) {
			return BPF_OK;
		}
		evt->arg_len = 0;
		evt->fd = 0;
		evt->bytes_len = bytes;
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