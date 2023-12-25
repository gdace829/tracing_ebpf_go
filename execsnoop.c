//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "execsnoop.h"

static const struct event empty_event = { };

// define hash map and perf event map
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, struct event);
} execs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

// tracepoint for sys_enter_execve.执行入口
SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter  *ctx)
{
	struct event *event;
	const char **args = (const char **)(ctx->args[1]);
	const char *argp;

	// get the PID 
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = (u32) id;
	// 获取当前进程的PID（进程标识符），并把它作为键存储到一个名为execs的哈希映射中，值是一个空的event结构体。
	// update the exec metadata to execs map 
	if (bpf_map_update_elem(&execs, &pid, &empty_event, BPF_NOEXIST)) {
		return 0;
	}
	//从哈希映射中查找event结构体，并更新它的元数据，包括PID，参数个数和参数总大小
	event = bpf_map_lookup_elem(&execs, &pid);
	if (!event) {
		return 0;
	}
	// update event metadata 
	event->pid = pid;

	return 0;
}

// tracepoint for sys_exit_execve.
SEC("tracepoint/syscalls/sys_exit_execve")
int tracepoint__syscalls__sys_exit_execve(struct trace_event_raw_sys_exit *ctx)
{
	u64 id;
	u32 pid;
	int ret;
	struct event *event;

	// 从execs哈希映射中根据当前进程的PID查找event结构体，如果没有找到则返回0
	id = bpf_get_current_pid_tgid();
	pid = (u32) id;
	event = bpf_map_lookup_elem(&execs, &pid);
	if (!event)
		return 0;

	// 从ctx结构体中获取系统调用的返回值，并更新event结构体的retval字段 从ctx结构体中获取当前进程的名称，并更新event结构体的comm字段。
	ret = ctx->ret;
	event->retval = ret;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	// 将event结构体的数据写入到events的perf事件中，events是一个类型为BPF_MAP_TYPE_PERF_EVENT_ARRAY的哈希映射，用于将数据发送到用户空间
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event,sizeof(*event));

	// cleanup exec from hash map 根据pid删除哈希映射 
	bpf_map_delete_elem(&execs, &pid);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";