#ifndef __KPROBE_H__
#define __KPROBE_H__

#define OBJ_STRING 0    /* String object. */
#define OBJ_LIST 1      /* List object. */
#define OBJ_SET 2       /* Set object. */
#define OBJ_ZSET 3      /* Sorted set object. */
#define OBJ_HASH 4      /* Hash object. */
#define INVALID 5      /* Hash object. */

#define _U(src, a, ...)		BPF_PROBE_READ_USER(src, a, ##__VA_ARGS__)
#define sdsEncodedObject(objptr) (objptr->encoding == OBJ_ENCODING_RAW || objptr->encoding == OBJ_ENCODING_EMBSTR)
#define AL_START_HEAD 0
#define AL_START_TAIL 1
#define MY_BPF_ARRAY_PERCPU(name, value_type) \
struct {													\
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); \
	__uint(key_size, sizeof(__u32)); \
	__uint(value_size, sizeof(value_type)); \
	__uint(max_entries, 1); \
	__uint(map_flags, 0); \
} name SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 100);
	__uint(map_flags, 0);
} reply_bytes_map SEC(".maps");

struct robj {
    unsigned type:4;
    unsigned encoding:4;
    unsigned lru:24; /* LRU time (relative to global lru_clock) or
                            * LFU data (least significant 8 bits frequency
                            * and most significant 16 bits access time). */
    int refcount;
    void *ptr;
};

struct client_t {
    uint64_t id;            /* Client incremental unique ID. */
    uint64_t flags;         /* Client flags: CLIENT_* macros. */
    struct connection *conn;//
    int resp;               /* RESP protocol version. Can be 2 or 3. */
    void *db;            /* Pointer to currently SELECTed DB. */
    void *name;             /* As set by CLIENT SETNAME. */
    void *lib_name;         /* The client library name as set by CLIENT SETINFO. */
    void *lib_ver;          /* The client library version as set by CLIENT SETINFO. */
    void* querybuf;           /* Buffer we use to accumulate client queries. */
    size_t qb_pos;          /* The position we have read in querybuf. */
    size_t querybuf_peak;   /* Recent (100ms or more) peak of querybuf size. */
    int argc;               /* Num of arguments of current command. */
    struct robj **argv;            /* Arguments of current command. */
    int argv_len;           /* Size of argv array (may be more than argc) */
    int original_argc;      /* Num of arguments of original command if arguments were rewritten. */
    struct robj **original_argv;   /* Arguments of original command if arguments were rewritten. */
};
typedef struct listNode {
    struct listNode *prev;
    struct listNode *next;
    void *value;
} listNode;

typedef struct listIter {
    listNode *next;
    int direction;
} listIter;
struct list {
    listNode *head;
    listNode *tail;
    void *(*dup)(void *ptr);
    void (*free)(void *ptr);
    int (*match)(void *ptr, void *key);
    unsigned long len;
} ;
typedef struct clientReplyBlock {
    size_t size, used;
    char buf[];
} clientReplyBlock;

#define listLength(l) ((l)->len)
struct client_data_pos {
    struct client_t *client;
    int buf_bos;
    int list_idx;
    int list_offset;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct client_data_pos));
	__uint(max_entries, 100);
	__uint(map_flags, 0);
} call_args_map SEC(".maps");


typedef enum {
    CONN_STATE_NONE = 0,
    CONN_STATE_CONNECTING,
    CONN_STATE_ACCEPTING,
    CONN_STATE_CONNECTED,
    CONN_STATE_CLOSED,
    CONN_STATE_ERROR
} ConnectionState;
struct connection {
    void *type;
    ConnectionState state;
    int last_errno;
    int fd;
    short int flags;
    short int refs;
    unsigned short int iovcnt;
    void *private_data;
};
typedef char *sds;
/* Note: sdshdr5 is never used, we just access the flags byte directly.
 * However is here to document the layout of type 5 SDS strings. */
struct __attribute__ ((__packed__)) sdshdr5 {
    unsigned char flags; /* 3 lsb of type, and 5 msb of string length */
    char buf[];
};
struct __attribute__ ((__packed__)) sdshdr8 {
    uint8_t len; /* used */
    uint8_t alloc; /* excluding the header and null terminator */
    unsigned char flags; /* 3 lsb of type, 5 unused bits */
    char buf[];
};
struct __attribute__ ((__packed__)) sdshdr16 {
    uint16_t len; /* used */
    uint16_t alloc; /* excluding the header and null terminator */
    unsigned char flags; /* 3 lsb of type, 5 unused bits */
    char buf[];
};
struct __attribute__ ((__packed__)) sdshdr32 {
    uint32_t len; /* used */
    uint32_t alloc; /* excluding the header and null terminator */
    unsigned char flags; /* 3 lsb of type, 5 unused bits */
    char buf[];
};
struct __attribute__ ((__packed__)) sdshdr64 {
    uint64_t len; /* used */
    uint64_t alloc; /* excluding the header and null terminator */
    unsigned char flags; /* 3 lsb of type, 5 unused bits */
    char buf[];
};

#define SDS_TYPE_5  0
#define SDS_TYPE_8  1
#define SDS_TYPE_16 2
#define SDS_TYPE_32 3
#define SDS_TYPE_64 4
#define SDS_TYPE_MASK 7
#define SDS_TYPE_BITS 3
#define SDS_HDR_VAR(T,s) struct sdshdr##T *sh = (void*)((s)-(sizeof(struct sdshdr##T)));
#define SDS_HDR(T,s) ((struct sdshdr##T *)((s)-(sizeof(struct sdshdr##T))))
#define SDS_TYPE_5_LEN(f) ((f)>>SDS_TYPE_BITS)

static __always_inline size_t sdslen(const sds s) {
    size_t len;
    unsigned char flags ;
    bpf_probe_read_user(&flags, 1, ((void*)s) - 1);
    if ((flags & SDS_TYPE_MASK) == SDS_TYPE_5) {  
            return SDS_TYPE_5_LEN(flags);  
    } else if ((flags & SDS_TYPE_MASK) == SDS_TYPE_8) {  
        struct sdshdr8* hdr = SDS_HDR(8, s);  
        len = _U(hdr, len);  
        return len;  
    } else if ((flags & SDS_TYPE_MASK) == SDS_TYPE_16) {  
        struct sdshdr16* hdr = SDS_HDR(16, s);  
        len = _U(hdr, len);  
        return len;  
    } else if ((flags & SDS_TYPE_MASK) == SDS_TYPE_32) {  
        struct sdshdr32* hdr = SDS_HDR(32, s);  
        len = _U(hdr, len);  
        return len;  
    } else if ((flags & SDS_TYPE_MASK) == SDS_TYPE_64) {  
        struct sdshdr64* hdr = SDS_HDR(64, s);  
        len = _U(hdr, len);  
        return len;  
    } else {  
        return 0;  
    }
}


static __always_inline void* sdsbuf(const sds s) {
    unsigned char flags ;
    bpf_probe_read_user(&flags, 1, ((void*)s) - 1);
    switch(flags&SDS_TYPE_MASK) {
        case SDS_TYPE_5:
            return NULL;
        case SDS_TYPE_8:
            {struct sdshdr8* hdr = SDS_HDR(8,s);
            void* buf = NULL;
            bpf_probe_read_user(&buf, sizeof(buf), (void*)hdr+ offsetof(struct sdshdr8, buf));
            return buf;}
        case SDS_TYPE_16:
            {struct sdshdr16* hdr = SDS_HDR(16,s);
            void* buf = NULL;
            bpf_probe_read_user(&buf, sizeof(buf), (void*)hdr+ offsetof(struct sdshdr16, buf));
            return buf;}
            // return SDS_HDR(16,s)->buf;
        case SDS_TYPE_32:
            {struct sdshdr32* hdr = SDS_HDR(32,s);
            void* buf = NULL;
            bpf_probe_read_user(&buf, sizeof(buf), (void*)hdr+ offsetof(struct sdshdr32, buf));
            return buf;}
            // return SDS_HDR(32,s)->buf;
        case SDS_TYPE_64:
            {struct sdshdr64* hdr = SDS_HDR(64,s);
            void* buf = NULL;
            bpf_probe_read_user(&buf, sizeof(buf), (void*)hdr+ offsetof(struct sdshdr64, buf));
            return buf;}
            // return SDS_HDR(64,s)->buf;
    }
    return 0;
}
#define BIGKEYLOG_ENTRY_MAX_STRING 6
#define MAX_STRING_LEN 160
#define MAX_ARGS_LEN 16

struct bigkey_arg {
    unsigned type;
    unsigned encoding;
    char arg0[MAX_STRING_LEN];
    bool trucated;
    int len;
};

struct bigkey_log {
    struct bigkey_arg bigkey_args[MAX_ARGS_LEN];
    u32 fd;
    int arg_len;
    int bytes_len;
};

MY_BPF_ARRAY_PERCPU(bigkey_log_stack_map, struct bigkey_log)

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} bigkey_event_map SEC(".maps");
#endif		
