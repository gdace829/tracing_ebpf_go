// This program demonstrates attaching an eBPF program to a kernel symbol.
// The eBPF program will be attached to the start of the sys_execve
// kernel function and prints out the number of times it has been called
// every second.
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf execsnoop.c

// 定义一个handleEvent函数，用于处理从perf事件缓冲区中读取到的event数据
func handleEvent(data []byte) {
	// 解码event数据
	var e bpfEvent
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &e); err != nil {
		log.Printf("failed to decode event: %s", err)
		return
	}
	// 打印event数据
	log.Printf("pid: %d, retval: %d, comm: %s\n", e.Pid, e.Retval, unix.ByteSliceToString(e.Comm[:]))
}

func main() {

	// Name of the kernel function to trace. 需要追踪的内核函数名称
	t1 := "sys_enter_execve"
	t2 := "sys_exit_execve"
	// Allow the current process to lock memory for eBPF resources.为了ebpf锁内存
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// 初始化ebpf程序
	objs := bpfObjects{}
	// 将预先编译的ebpf程序和map加载到内核中
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Open a Kprobe at the entry point of the kernel function and attach the
	// pre-compiled program. Each time the kernel function enters, the program
	// will increment the execution counter by 1. The read loop below polls this
	// map value once per second.将函数fn和入口出口trace绑定
	enter, err := link.Tracepoint("syscalls", t1, objs.TracepointSyscallsSysEnterExecve, nil)
	if err != nil {
		log.Fatalf("opening enter: %s", err)
	}
	defer enter.Close()
	exit, err := link.Tracepoint("syscalls", t2, objs.TracepointSyscallsSysExitExecve, nil)
	if err != nil {
		log.Fatalf("opening exit: %s", err)
	}
	defer exit.Close()
	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	log.Println("Waiting for events..")
	rd, _ := perf.NewReader(objs.Events, os.Getpagesize())
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Printf("reading from perf event reader: %s", err)
			continue
		}
		if record.LostSamples != 0 {
			log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
			continue
		}
		handleEvent(record.RawSample)
	}
}
