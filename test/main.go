//go:build linux

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang Syscalltracer syscall_tracer.c

package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	TargetPID  = 750849
	MaxDataLen = 4096
)

type SyscallEvent struct {
	PID       uint32
	FD        uint32
	Len       uint32
	RetVal    uint32
	IsWrite   uint8
	IsSpecial uint8
	Comm      [16]byte
	Data      [MaxDataLen]byte
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	// 移除内存限制
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock rlimit: %v", err)
	}

	// 加载eBPF程序
	spec, err := LoadSyscalltracer()
	if err != nil {
		log.Fatalf("Failed to load eBPF spec: %v", err)
	}

	objs := SyscalltracerObjects{}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// 附加tracepoint
	links := []link.Link{}

	// write系统调用
	linkWriteEnter, err := link.Tracepoint("syscalls", "sys_enter_write", objs.TraceWriteEnter, nil)
	if err != nil {
		log.Fatalf("Failed to attach write enter tracepoint: %v", err)
	}
	links = append(links, linkWriteEnter)

	linkWriteExit, err := link.Tracepoint("syscalls", "sys_exit_write", objs.TraceWriteExit, nil)
	if err != nil {
		log.Fatalf("Failed to attach write exit tracepoint: %v", err)
	}
	links = append(links, linkWriteExit)

	// read系统调用
	linkReadEnter, err := link.Tracepoint("syscalls", "sys_enter_read", objs.TraceReadEnter, nil)
	if err != nil {
		log.Fatalf("Failed to attach read enter tracepoint: %v", err)
	}
	links = append(links, linkReadEnter)

	linkReadExit, err := link.Tracepoint("syscalls", "sys_exit_read", objs.TraceReadExit, nil)
	if err != nil {
		log.Fatalf("Failed to attach read exit tracepoint: %v", err)
	}
	links = append(links, linkReadExit)

	// send系统调用
	linkSendEnter, err := link.Tracepoint("syscalls", "sys_enter_send", objs.TraceSendEnter, nil)
	if err != nil {
		log.Printf("Warning: Failed to attach send enter tracepoint: %v", err)
	} else {
		links = append(links, linkSendEnter)
	}

	linkSendExit, err := link.Tracepoint("syscalls", "sys_exit_send", objs.TraceSendExit, nil)
	if err != nil {
		log.Printf("Warning: Failed to attach send exit tracepoint: %v", err)
	} else {
		links = append(links, linkSendExit)
	}

	// sendto系统调用
	linkSendtoEnter, err := link.Tracepoint("syscalls", "sys_enter_sendto", objs.TraceSendtoEnter, nil)
	if err != nil {
		log.Printf("Warning: Failed to attach sendto enter tracepoint: %v", err)
	} else {
		links = append(links, linkSendtoEnter)
	}

	linkSendtoExit, err := link.Tracepoint("syscalls", "sys_exit_sendto", objs.TraceSendtoExit, nil)
	if err != nil {
		log.Printf("Warning: Failed to attach sendto exit tracepoint: %v", err)
	} else {
		links = append(links, linkSendtoExit)
	}

	// sendmsg系统调用
	linkSendmsgEnter, err := link.Tracepoint("syscalls", "sys_enter_sendmsg", objs.TraceSendmsgEnter, nil)
	if err != nil {
		log.Printf("Warning: Failed to attach sendmsg enter tracepoint: %v", err)
	} else {
		links = append(links, linkSendmsgEnter)
	}

	linkSendmsgExit, err := link.Tracepoint("syscalls", "sys_exit_sendmsg", objs.TraceSendmsgExit, nil)
	if err != nil {
		log.Printf("Warning: Failed to attach sendmsg exit tracepoint: %v", err)
	} else {
		links = append(links, linkSendmsgExit)
	}

	// writev系统调用
	linkWritevEnter, err := link.Tracepoint("syscalls", "sys_enter_writev", objs.TraceWritevEnter, nil)
	if err != nil {
		log.Printf("Warning: Failed to attach writev enter tracepoint: %v", err)
	} else {
		links = append(links, linkWritevEnter)
	}

	linkWritevExit, err := link.Tracepoint("syscalls", "sys_exit_writev", objs.TraceWritevExit, nil)
	if err != nil {
		log.Printf("Warning: Failed to attach writev exit tracepoint: %v", err)
	} else {
		links = append(links, linkWritevExit)
	}

	// readv系统调用
	linkReadvEnter, err := link.Tracepoint("syscalls", "sys_enter_readv", objs.TraceReadvEnter, nil)
	if err != nil {
		log.Printf("Warning: Failed to attach readv enter tracepoint: %v", err)
	} else {
		links = append(links, linkReadvEnter)
	}

	linkReadvExit, err := link.Tracepoint("syscalls", "sys_exit_readv", objs.TraceReadvExit, nil)
	if err != nil {
		log.Printf("Warning: Failed to attach readv exit tracepoint: %v", err)
	} else {
		links = append(links, linkReadvExit)
	}

	// sendfile系统调用
	linkSendfileEnter, err := link.Tracepoint("syscalls", "sys_enter_sendfile", objs.TraceSendfileEnter, nil)
	if err != nil {
		log.Printf("Warning: Failed to attach sendfile enter tracepoint: %v", err)
	} else {
		links = append(links, linkSendfileEnter)
	}

	linkSendfileExit, err := link.Tracepoint("syscalls", "sys_exit_sendfile", objs.TraceSendfileExit, nil)
	if err != nil {
		log.Printf("Warning: Failed to attach sendfile exit tracepoint: %v", err)
	} else {
		links = append(links, linkSendfileExit)
	}

	defer func() {
		for _, l := range links {
			l.Close()
		}
	}()

	// 打开ring buffer reader
	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("Failed to create ring buffer reader: %v", err)
	}
	defer reader.Close()

	log.Printf("开始监控所有Elasticsearch/Java相关进程的网络系统调用...")
	log.Printf("主要关注PID %d，但也会显示其他相关进程", TargetPID)
	log.Printf("同时启动网络包捕获来获取HTTP响应数据...")
	log.Printf("按Ctrl+C退出")

	// 启动网络包捕获（使用v2版本）
	startPacketCaptureV2()

	// 处理信号
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		log.Printf("收到信号，正在退出...")
		cancel()
	}()

	// 读取事件
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				record, err := reader.Read()
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					log.Printf("读取ring buffer错误: %v", err)
					continue
				}

				if len(record.RawSample) < int(binary.Size(SyscallEvent{})) {
					continue
				}

				var event SyscallEvent
				if err := binary.Read(strings.NewReader(string(record.RawSample)), binary.LittleEndian, &event); err != nil {
					log.Printf("解析事件错误: %v", err)
					continue
				}

				// 打印事件信息
				direction := "READ"
				if event.IsWrite == 1 {
					direction = "WRITE"
				}

				comm := string(event.Comm[:])
				if idx := strings.IndexByte(comm, 0); idx != -1 {
					comm = comm[:idx]
				}

				// 获取数据预览（最大511字节）
				dataPreview := ""
				if event.RetVal > 0 {
					// 获取实际可用数据长度，限制为511字节
					availableLen := event.RetVal & 511 // 与BPF中的限制保持一致
					if availableLen > 0 {
						// 显示前64字节的预览
						previewLen := availableLen
						if previewLen > 64 {
							previewLen = 64
						}
						dataPreview = fmt.Sprintf("%q", string(event.Data[:previewLen]))
						if event.RetVal > 511 {
							dataPreview += fmt.Sprintf(" [truncated, total: %d bytes]", event.RetVal)
						}
					}
				}

				log.Printf("[%s] PID=%d, Comm=%s, FD=%d, Len=%d, RetVal=%d, Data=%s",
					direction, event.PID, comm, event.FD, event.Len, event.RetVal, dataPreview)

				// 特别关注Len=0但RetVal>0的情况，这可能是特殊的系统调用
				if event.IsSpecial == 1 {
					log.Printf("!!! 特殊系统调用检测 !!! PID=%d, FD=%d, Len=%d, RetVal=%d",
						event.PID, event.FD, event.Len, event.RetVal)

					// 对于特殊系统调用，我们需要使用其他方法来获取数据
					if event.PID == TargetPID && event.FD == 226 && event.RetVal == 334 {
						log.Printf("*** 找到目标HTTP响应！但无法直接读取数据 ***")
						log.Printf("建议：在TCP层面监控FD=%d的数据流", event.FD)
					}
				}

				// 重点关注目标PID的大数据包
				if event.PID == TargetPID && event.RetVal > 50 && event.IsWrite == 1 {
					log.Printf("*** 目标PID的大数据包 *** FD=%d, 长度=%d", event.FD, event.RetVal)
					// 显示可用的数据内容
					availableLen := event.RetVal & 511
					if availableLen > 0 {
						dataStr := string(event.Data[:availableLen])
						log.Printf("可用数据: %s", dataStr)
					}
				}

				// 检测HTTP内容
				if event.RetVal > 0 && event.IsWrite == 1 {
					availableLen := event.RetVal & 511
					if availableLen > 0 {
						dataStr := string(event.Data[:availableLen])
						if strings.Contains(dataStr, "HTTP") || strings.Contains(dataStr, "Content-Type") ||
							strings.Contains(dataStr, "json") || strings.Contains(dataStr, "took") {
							log.Printf("=== 可能的HTTP响应 (PID=%d, FD=%d, 长度=%d) ===", event.PID, event.FD, event.RetVal)
							log.Printf("%s", dataStr)
							log.Printf("=== 数据结束 ===")
						}
					}
				}
			}
		}
	}()

	// 等待退出信号
	<-ctx.Done()
	time.Sleep(100 * time.Millisecond) // 确保最后的事件被处理
	log.Printf("程序退出")
}
