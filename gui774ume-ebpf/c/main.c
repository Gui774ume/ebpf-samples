#include "bpf.h"
#include "bpf_helpers.h"

SEC("kprobe/do_sys_open")
int kprobe__do_sys_open(void *ctx)
{
    char format[] = "hello!\n";
    bpf_trace_printk(format, sizeof(format));
    return 0;
};

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
