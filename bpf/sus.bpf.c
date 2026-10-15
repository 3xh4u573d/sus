#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define PATH_LEN 256
#define ARGS_LEN 512

#define AF_UNIX  1
#define AF_INET  2
#define AF_INET6 10

enum event_type {
	EV_EXEC = 1,
	EV_OPEN,
	EV_CONNECT,
	EV_UNLINK,
	EV_RENAME,
	EV_MKDIR,
	EV_CHMOD,
	EV_SYMLINK,
	EV_BIND,
	EV_SENDTO,
	EV_PTRACE,
	EV_SETUID,
	EV_SETRESUID,
	EV_MOUNT,
	EV_MEMFD,
	EV_MODULE,
	EV_DNS,
	EV_DNSQ,
	EV_STAT,
};

struct event {
	__u64 ts;
	__u32 type;
	__u32 pid;
	__u32 ppid;
	__u32 flags;
	__u32 arglen;
	__s32 result;
	__u32 aux;
	__u16 family;
	__u16 port;
	__u8 addr[16];
	char comm[16];
	char path[PATH_LEN];
	char args[ARGS_LEN];
};

_Static_assert(sizeof(struct event) == 840, "event layout changed");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} target SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} dropped SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 26);
} events SEC(".maps");

static __always_inline bool in_target(void)
{
	__u32 zero = 0;
	__u64 *want = bpf_map_lookup_elem(&target, &zero);

	return want && *want != 0 && bpf_get_current_cgroup_id() == *want;
}

static __always_inline struct event *start_event(__u32 type)
{
	__u32 zero = 0;

	if (!in_target())
		return NULL;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		__u64 *cnt = bpf_map_lookup_elem(&dropped, &zero);
		if (cnt)
			__sync_fetch_and_add(cnt, 1);
		return NULL;
	}

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	e->ts = bpf_ktime_get_ns();
	e->aux = 0;
	e->type = type;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->flags = 0;
	e->arglen = 0;
	e->result = 0;
	e->family = 0;
	e->port = 0;
	__builtin_memset(e->addr, 0, sizeof(e->addr));
	e->path[0] = 0;
	e->args[0] = 0;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	return e;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(handle_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
	struct event *e = start_event(EV_EXEC);
	if (!e)
		return 0;

	bpf_probe_read_kernel_str(e->path, sizeof(e->path), BPF_CORE_READ(bprm, filename));

	unsigned long start = BPF_CORE_READ(p, mm, arg_start);
	unsigned long end = BPF_CORE_READ(p, mm, arg_end);
	unsigned long len = end > start ? end - start : 0;

	if (len > ARGS_LEN) {
		len = ARGS_LEN;
		e->flags = 1;
	}
	if (len && bpf_probe_read_user(e->args, len, (void *)start) == 0)
		e->arglen = len;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

#define SYSCALL_FEXIT(name) \
	SEC("fexit/__x64_sys_" #name) \
	int BPF_PROG(handle_##name, struct pt_regs *regs, long ret)

#define ARG1 ((long)BPF_CORE_READ(regs, di))
#define ARG2 ((long)BPF_CORE_READ(regs, si))
#define ARG3 ((long)BPF_CORE_READ(regs, dx))
#define ARG4 ((long)BPF_CORE_READ(regs, r10))
#define ARG5 ((long)BPF_CORE_READ(regs, r8))
#define UPTR(x) ((const void *)(x))

static __always_inline int emit_path(__u32 type, long ret, const void *path, __u32 flags, __u32 aux)
{
	struct event *e = start_event(type);
	if (!e)
		return 0;

	e->result = ret;
	e->flags = flags;
	e->aux = aux;
	bpf_probe_read_user_str(e->path, sizeof(e->path), path);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

static __always_inline int emit_path2(__u32 type, long ret, const void *path, const void *path2, __u32 flags)
{
	struct event *e = start_event(type);
	if (!e)
		return 0;

	e->result = ret;
	e->flags = flags;
	bpf_probe_read_user_str(e->path, sizeof(e->path), path);
	if (path2)
		bpf_probe_read_user_str(e->args, sizeof(e->args), path2);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

static __always_inline int emit_nums(__u32 type, long ret, __u32 a, __u32 b)
{
	struct event *e = start_event(type);
	if (!e)
		return 0;

	e->result = ret;
	e->flags = a;
	e->aux = b;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

static __always_inline int fill_sockaddr(struct event *e, const void *uaddr)
{
	__u16 family = 0;

	if (bpf_probe_read_user(&family, sizeof(family), uaddr) < 0)
		return -1;

	e->family = family;

	if (family == AF_INET) {
		__u8 raw[8];

		if (bpf_probe_read_user(raw, sizeof(raw), uaddr) < 0)
			return -1;
		e->port = ((__u16)raw[2] << 8) | raw[3];
		__builtin_memcpy(e->addr, raw + 4, 4);
	} else if (family == AF_INET6) {
		__u8 raw[24];

		if (bpf_probe_read_user(raw, sizeof(raw), uaddr) < 0)
			return -1;
		e->port = ((__u16)raw[2] << 8) | raw[3];
		__builtin_memcpy(e->addr, raw + 8, 16);
	} else if (family == AF_UNIX) {
		bpf_probe_read_user_str(e->path, sizeof(e->path), (const char *)uaddr + 2);
	} else {
		return -1;
	}
	return 0;
}

static __always_inline int emit_addr(__u32 type, long ret, const void *uaddr)
{
	if (!uaddr)
		return 0;

	struct event *e = start_event(type);
	if (!e)
		return 0;

	e->result = ret;
	if (fill_sockaddr(e, uaddr) < 0) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SYSCALL_FEXIT(openat)  { return emit_path(EV_OPEN, ret, UPTR(ARG2), ARG3, 0); }
SYSCALL_FEXIT(openat2)
{
	__u64 flags = 0;

	bpf_probe_read_user(&flags, sizeof(flags), UPTR(ARG3));
	return emit_path(EV_OPEN, ret, UPTR(ARG2), (__u32)flags, 0);
}
SYSCALL_FEXIT(unlinkat) { return emit_path(EV_UNLINK, ret, UPTR(ARG2), ARG3, 0); }
SYSCALL_FEXIT(unlink)   { return emit_path(EV_UNLINK, ret, UPTR(ARG1), 0, 0); }
SYSCALL_FEXIT(rmdir)    { return emit_path(EV_UNLINK, ret, UPTR(ARG1), 0x200, 0); }

SYSCALL_FEXIT(rename)    { return emit_path2(EV_RENAME, ret, UPTR(ARG1), UPTR(ARG2), 0); }
SYSCALL_FEXIT(renameat)  { return emit_path2(EV_RENAME, ret, UPTR(ARG2), UPTR(ARG4), 0); }
SYSCALL_FEXIT(renameat2) { return emit_path2(EV_RENAME, ret, UPTR(ARG2), UPTR(ARG4), ARG5); }

SYSCALL_FEXIT(mkdir)   { return emit_path(EV_MKDIR, ret, UPTR(ARG1), ARG2, 0); }
SYSCALL_FEXIT(mkdirat) { return emit_path(EV_MKDIR, ret, UPTR(ARG2), ARG3, 0); }

SYSCALL_FEXIT(chmod)      { return emit_path(EV_CHMOD, ret, UPTR(ARG1), ARG2, 0); }
SYSCALL_FEXIT(fchmodat)   { return emit_path(EV_CHMOD, ret, UPTR(ARG2), ARG3, 0); }
SYSCALL_FEXIT(fchmodat2)  { return emit_path(EV_CHMOD, ret, UPTR(ARG2), ARG3, 0); }

SYSCALL_FEXIT(symlink)   { return emit_path2(EV_SYMLINK, ret, UPTR(ARG2), UPTR(ARG1), 0); }
SYSCALL_FEXIT(symlinkat) { return emit_path2(EV_SYMLINK, ret, UPTR(ARG3), UPTR(ARG1), 0); }

static __always_inline int emit_probe(long ret, const void *path)
{
	char first = 0;

	if (bpf_probe_read_user(&first, sizeof(first), path) < 0 || !first)
		return 0;
	return emit_path(EV_STAT, ret, path, 0, 0);
}

SYSCALL_FEXIT(newstat)    { return emit_probe(ret, UPTR(ARG1)); }
SYSCALL_FEXIT(newlstat)   { return emit_probe(ret, UPTR(ARG1)); }
SYSCALL_FEXIT(newfstatat) { return emit_probe(ret, UPTR(ARG2)); }
SYSCALL_FEXIT(statx)      { return emit_probe(ret, UPTR(ARG2)); }
SYSCALL_FEXIT(access)     { return emit_probe(ret, UPTR(ARG1)); }
SYSCALL_FEXIT(faccessat)  { return emit_probe(ret, UPTR(ARG2)); }
SYSCALL_FEXIT(faccessat2) { return emit_probe(ret, UPTR(ARG2)); }

SYSCALL_FEXIT(connect) { return emit_addr(EV_CONNECT, ret, UPTR(ARG2)); }
SYSCALL_FEXIT(bind)    { return emit_addr(EV_BIND, ret, UPTR(ARG2)); }
SYSCALL_FEXIT(sendto)  { return emit_addr(EV_SENDTO, ret, UPTR(ARG5)); }

SYSCALL_FEXIT(ptrace)      { return emit_nums(EV_PTRACE, ret, ARG1, ARG2); }
SYSCALL_FEXIT(setuid)      { return emit_nums(EV_SETUID, ret, ARG1, 0); }
SYSCALL_FEXIT(setresuid)   { return emit_nums(EV_SETRESUID, ret, ARG1, ARG2); }
SYSCALL_FEXIT(mount)       { return emit_path2(EV_MOUNT, ret, UPTR(ARG2), UPTR(ARG3), ARG4); }
SYSCALL_FEXIT(memfd_create) { return emit_path(EV_MEMFD, ret, UPTR(ARG1), ARG2, 0); }
SYSCALL_FEXIT(init_module)  { return emit_nums(EV_MODULE, ret, 0, 0); }
SYSCALL_FEXIT(finit_module) { return emit_nums(EV_MODULE, ret, ARG1, 1); }

struct gai_args {
	__u64 node;
	__u64 res;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, struct gai_args);
} gai SEC(".maps");

struct user_addrinfo {
	int ai_flags;
	int ai_family;
	int ai_socktype;
	int ai_protocol;
	__u32 ai_addrlen;
	void *ai_addr;
	char *ai_canonname;
	struct user_addrinfo *ai_next;
};

SEC("uprobe/getaddrinfo")
int BPF_KPROBE(handle_gai_enter, const char *node, const char *service, const void *hints, void **res)
{
	if (!node || !in_target())
		return 0;

	__u64 id = bpf_get_current_pid_tgid();
	struct gai_args a = { .node = (__u64)node, .res = (__u64)res };

	bpf_map_update_elem(&gai, &id, &a, BPF_ANY);
	return 0;
}

SEC("uretprobe/getaddrinfo")
int BPF_KRETPROBE(handle_gai_exit, int ret)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct gai_args *a = bpf_map_lookup_elem(&gai, &id);
	if (!a)
		return 0;

	__u64 node = a->node;
	__u64 resp = a->res;

	bpf_map_delete_elem(&gai, &id);

	struct event *q = start_event(EV_DNSQ);
	if (q) {
		q->result = ret;
		bpf_probe_read_user_str(q->path, sizeof(q->path), (const char *)node);
		bpf_ringbuf_submit(q, 0);
	}

	if (ret != 0 || !resp)
		return 0;

	struct user_addrinfo *ai = NULL;
	if (bpf_probe_read_user(&ai, sizeof(ai), (void *)resp) < 0)
		return 0;

#pragma unroll
	for (int i = 0; i < 8; i++) {
		struct user_addrinfo cur;

		if (!ai || bpf_probe_read_user(&cur, sizeof(cur), ai) < 0)
			break;

		if (cur.ai_addr && (cur.ai_family == AF_INET || cur.ai_family == AF_INET6)) {
			struct event *e = start_event(EV_DNS);
			if (!e)
				break;

			bpf_probe_read_user_str(e->path, sizeof(e->path), (const char *)node);
			if (fill_sockaddr(e, cur.ai_addr) < 0)
				bpf_ringbuf_discard(e, 0);
			else
				bpf_ringbuf_submit(e, 0);
		}
		ai = cur.ai_next;
	}
	return 0;
}
