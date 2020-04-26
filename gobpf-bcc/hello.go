package main

import (
	"fmt"
	"os"
	"os/signal"

	bpf "github.com/iovisor/gobpf/bcc"
)

import "C"

const source string = `
#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>

int trace_entry(struct pt_regs *ctx, int dfd, const char __user *filename, int flags)
{
	bpf_trace_printk("gobpf-bcc hello!\n");
    return 0;
};
`

func main() {
	m := bpf.NewModule(source, []string{})
	defer m.Close()

	myFuncTcpt, err := m.LoadKprobe("trace_entry")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load my_func: %s\n", err)
		os.Exit(1)
	}

	err = m.AttachKprobe("do_sys_open", myFuncTcpt, -1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach syscalls:sys_enter_execve: %s\n", err)
		os.Exit(1)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	<-sig
}
