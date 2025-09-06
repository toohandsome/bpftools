//go:build linux
// +build linux

package ebpf

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/myserver/go-server/ebpf/internal/monitor"
	"github.com/myserver/go-server/ebpf/internal/parser"
	"github.com/myserver/go-server/ebpf/internal/stream"
)

type httpEvent struct {
	PID       uint32
	Comm      [16]byte
	Len       uint32
	OrigLen   uint32
	FD        int32
	Direction uint8
	Pad       [3]byte
	Data      [4096]byte
}

// lightweight entry for de-duplication window
type dedupEntry struct {
	bestLen int
	ts      time.Time
}

// 拼接状态管理
type spliceState struct {
	payload     strings.Builder // 累积的载荷
	firstEvent  httpEvent       // 第一个事件（用于最终输出）
	lastUpdate  time.Time       // 最后更新时间
	expectedLen int             // 期望的Content-Length（如果解析到），含 header+body 总长度
	isComplete  bool            // 是否已完成（有完整的header+body）
	origTotal   int             // 累计的原始长度（各次 OrigLen 之和）
	isChunked   bool            // 是否为 chunked 传输
	isResponse  bool            // 是否为响应（根据起始行判断）
}

// 配置常量
const (
	// 缓存大小限制
	maxSpliceBufferEntries = 10000 // 最大拼接缓存条目数
	maxDedupEntries        = 5000  // 最大去重缓存条目数

	// 清理间隔
	cleanupInterval = 300 * time.Second // 缓存清理间隔
)

type HTTPMonitor struct {
	objs    *ebpf.Collection
	reader  *ringbuf.Reader
	links   []link.Link
	cancel  context.CancelFunc
	OnEvent func([]byte) // JSON bytes for frontend

	// 混合架构组件
	streamProcessor    *stream.HTTPStreamProcessor
	packetConverter    *stream.PacketConverter
	useStreamProcessor bool // 是否启用流处理器

	// 线程安全的缓存结构（保留用于降级场景）
	// de-dup cache for short window to avoid duplicate recv events (e.g., wget recvmsg+read)
	dedupMutex sync.RWMutex
	dedup      map[string]dedupEntry

	// inode -> tuple snapshot from /proc/net/tcp{,6}
	tcpSnapMutex sync.RWMutex
	tcpSnap      map[string]connTuple
	tcpSnapAt    time.Time

	// 拼接状态缓存：key = "pid:fd:direction", value = spliceState（降级使用）
	spliceBufferMutex sync.RWMutex
	spliceBuffer      map[string]*spliceState

	// 调试日志：将原始 ringbuf 数据与事件完整内容写入文件
	debugFile *os.File
	rawLog    *log.Logger

	// 清理控制
	cleanupDone chan struct{}

	// 流清理定时器
	flushTicker *time.Ticker
}

type connTuple struct {
	lIP   string
	lPort int
	rIP   string
	rPort int
}

func (m *HTTPMonitor) refreshTCPSnapshot() {
	m.tcpSnapMutex.Lock()
	defer m.tcpSnapMutex.Unlock()

	// refresh at most once per second
	if time.Since(m.tcpSnapAt) < time.Second && m.tcpSnap != nil {
		return
	}
	snap := make(map[string]connTuple, 4096)
	// IPv4
	if f, err := os.Open("/proc/net/tcp"); err == nil {
		scanner := bufio.NewScanner(f)
		// skip header
		if scanner.Scan() {
			// header
		}
		for scanner.Scan() {
			line := scanner.Text()
			// fields: sl local_address rem_address st ... inode
			parts := strings.Fields(line)
			if len(parts) < 10 {
				continue
			}
			la := parts[1]
			ra := parts[2]
			inode := parts[9]
			lip, lport := parseHexAddr4(la)
			rip, rport := parseHexAddr4(ra)
			if lip != "" {
				snap[inode] = connTuple{lIP: lip, lPort: lport, rIP: rip, rPort: rport}
			}
		}
		_ = f.Close()
	}
	// IPv6
	if f, err := os.Open("/proc/net/tcp6"); err == nil {
		scanner := bufio.NewScanner(f)
		if scanner.Scan() {
		}
		for scanner.Scan() {
			line := scanner.Text()
			parts := strings.Fields(line)
			if len(parts) < 10 {
				continue
			}
			la := parts[1]
			ra := parts[2]
			inode := parts[9]
			lip, lport := parseHexAddr6(la)
			rip, rport := parseHexAddr6(ra)
			if lip != "" {
				snap[inode] = connTuple{lIP: lip, lPort: lport, rIP: rip, rPort: rport}
			}
		}
		_ = f.Close()
	}
	m.tcpSnap = snap
	m.tcpSnapAt = time.Now()
}

func parseHexAddr4(s string) (string, int) {
	// s like: "0100007F:1F90" (little-endian IPv4)
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return "", 0
	}
	iphex := parts[0]
	porthex := parts[1]
	if len(iphex) != 8 {
		return "", 0
	}
	// bytes reversed
	b := make([]byte, 4)
	for i := 0; i < 4; i++ {
		v, err := strconv.ParseUint(iphex[i*2:i*2+2], 16, 8)
		if err != nil {
			return "", 0
		}
		b[3-i] = byte(v)
	}
	ip := net.IPv4(b[0], b[1], b[2], b[3]).String()
	p, err := strconv.ParseUint(porthex, 16, 16)
	if err != nil {
		return ip, 0
	}
	return ip, int(p)
}

func parseHexAddr6(s string) (string, int) {
	// s like: 00000000000000000000000000000001:1F90
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return "", 0
	}
	iphex := parts[0]
	porthex := parts[1]
	if len(iphex) != 32 {
		return "", 0
	}
	// IPv6 is in network byte order (big-endian) but grouped; convert 16 bytes
	b := make([]byte, 16)
	for i := 0; i < 16; i++ {
		v, err := strconv.ParseUint(iphex[i*2:i*2+2], 16, 8)
		if err != nil {
			return "", 0
		}
		b[i] = byte(v)
	}
	ip := net.IP(b).String()
	p, err := strconv.ParseUint(porthex, 16, 16)
	if err != nil {
		return ip, 0
	}
	return ip, int(p)
}

func (m *HTTPMonitor) resolvePIDFD(pid int, fd int) (connTuple, bool) {
	// /proc/<pid>/fd/<fd> -> socket:[inode]
	link := fmt.Sprintf("/proc/%d/fd/%d", pid, fd)
	target, err := os.Readlink(link)
	if err != nil {
		return connTuple{}, false
	}
	// expect like socket:[12345]
	i1 := strings.Index(target, "[")
	i2 := strings.Index(target, "]")
	if i1 < 0 || i2 <= i1+1 {
		return connTuple{}, false
	}
	inode := target[i1+1 : i2]
	m.refreshTCPSnapshot()

	m.tcpSnapMutex.RLock()
	defer m.tcpSnapMutex.RUnlock()
	t, ok := m.tcpSnap[inode]
	return t, ok
}

func (m *HTTPMonitor) Close() {
	// 停止清理goroutine
	if m.cleanupDone != nil {
		close(m.cleanupDone)
	}

	// 停止流清理定时器
	if m.flushTicker != nil {
		m.flushTicker.Stop()
	}

	if m.reader != nil {
		m.reader.Close()
	}
	for _, l := range m.links {
		_ = l.Close()
	}
	if m.objs != nil {
		m.objs.Close()
	}
	if m.cancel != nil {
		m.cancel()
	}
	if m.debugFile != nil {
		_ = m.debugFile.Close()
	}

	// 仅当显式开启 EBPFD_RAW_DEBUG 时，才记录原始样本与详细数据到 log.log
	if os.Getenv("EBPFD_RAW_DEBUG") != "" {
		if f, err := os.OpenFile("log.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err != nil {
			log.Printf("open log.log failed: %v", err)
		} else {
			m.debugFile = f
			m.rawLog = log.New(f, "", log.LstdFlags|log.Lmicroseconds)
		}
	} else {
		m.debugFile = nil
		m.rawLog = nil
	}
}

func NewHTTPMonitor(selector monitor.ProcessSelector, onEvent func([]byte)) (*HTTPMonitor, error) {
	// Load pre-compiled object file built from internal/ebpf/bpf/http_monitor_v3.c
	spec, err := ebpf.LoadCollectionSpec("internal/ebpf/http_monitor_bpfel.o")
	if err != nil {
		return nil, fmt.Errorf("loading BPF spec: %w (ensure internal/ebpf/http_monitor_bpfel.o exists and is built from internal/ebpf/bpf/http_monitor_v3.c)", err)
	}

	objs, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("creating collection: %w", err)
	}

	m := &HTTPMonitor{
		objs:    objs,
		OnEvent: onEvent,
		links:   make([]link.Link, 0, 10),
		// init de-dup cache
		dedup:        make(map[string]dedupEntry, 128),
		tcpSnap:      make(map[string]connTuple),
		spliceBuffer: make(map[string]*spliceState),
		cleanupDone:  make(chan struct{}),
		// 初始化混合架构组件
		useStreamProcessor: true, // 默认启用流处理器
	}

	// 初始化gopacket流处理器
	m.streamProcessor = stream.NewHTTPStreamProcessor(onEvent)
	m.packetConverter = stream.NewPacketConverter()

	// 初始化原始数据日志文件
	if f, err := os.OpenFile("log.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err != nil {
		log.Printf("open log.log failed: %v", err)
	} else {
		m.debugFile = f
		m.rawLog = log.New(f, "", log.LstdFlags|log.Lmicroseconds)
	}

	// Configure kernel-side PID filtering when a PID is specified
	if pm, ok := objs.Maps["filter_enabled"]; ok && pm != nil {
		var key uint32 = 0
		var enabled uint8 = 0 // default: disabled (monitor all)
		if selector.PID != 0 {
			enabled = 1
		}
		if err := pm.Put(key, enabled); err != nil {
			log.Printf("failed to set filter_enabled: %v", err)
		}
	}
	if selector.PID != 0 {
		if pm, ok := objs.Maps["pid_filter"]; ok && pm != nil {
			pidKey := uint32(selector.PID)
			var one uint8 = 1
			if err := pm.Put(pidKey, one); err != nil {
				log.Printf("failed to update pid_filter for pid %d: %v", selector.PID, err)
			}
		}
	}

	// Attach all tracepoint programs defined in http_monitor_v3.c
	attachTP := func(section, category, name string) error {
		prog := objs.Programs[section]
		if prog == nil {
			// Program not found in object, skip attaching this one
			log.Printf("BPF program %s not found in object, skipping %s/%s", section, category, name)
			return nil
		}
		l, err := link.Tracepoint(category, name, prog, nil)
		if err != nil {
			// If the tracepoint doesn't exist on this kernel, skip gracefully
			if errors.Is(err, os.ErrNotExist) || strings.Contains(strings.ToLower(err.Error()), "no such file") || strings.Contains(strings.ToLower(err.Error()), "not found") {
				log.Printf("Tracepoint %s/%s not present on this kernel, skipping", category, name)
				return nil
			}
			return fmt.Errorf("attach %s/%s: %w", category, name, err)
		}
		m.links = append(m.links, l)
		return nil
	}

	// sys_enter_* for send and recv families
	if err := attachTP("tp_sys_enter_sendto", "syscalls", "sys_enter_sendto"); err != nil {
		m.Close()
		return nil, err
	}
	if err := attachTP("tp_sys_enter_send", "syscalls", "sys_enter_send"); err != nil {
		m.Close()
		return nil, err
	}
	if err := attachTP("tp_sys_enter_write", "syscalls", "sys_enter_write"); err != nil {
		m.Close()
		return nil, err
	}
	if err := attachTP("tp_sys_enter_writev", "syscalls", "sys_enter_writev"); err != nil {
		m.Close()
		return nil, err
	}
	if err := attachTP("tp_sys_enter_recvfrom", "syscalls", "sys_enter_recvfrom"); err != nil {
		m.Close()
		return nil, err
	}
	if err := attachTP("tp_sys_exit_recvfrom", "syscalls", "sys_exit_recvfrom"); err != nil {
		m.Close()
		return nil, err
	}
	if err := attachTP("tp_sys_enter_recv", "syscalls", "sys_enter_recv"); err != nil {
		m.Close()
		return nil, err
	}
	if err := attachTP("tp_sys_exit_recv", "syscalls", "sys_exit_recv"); err != nil {
		m.Close()
		return nil, err
	}
	if err := attachTP("tp_sys_enter_read", "syscalls", "sys_enter_read"); err != nil {
		m.Close()
		return nil, err
	}
	if err := attachTP("tp_sys_exit_read", "syscalls", "sys_exit_read"); err != nil {
		m.Close()
		return nil, err
	}
	// sendmsg/recvmsg support for tools like wget
	if err := attachTP("tp_sys_enter_sendmsg", "syscalls", "sys_enter_sendmsg"); err != nil {
		m.Close()
		return nil, err
	}
	if err := attachTP("tp_sys_enter_recvmsg", "syscalls", "sys_enter_recvmsg"); err != nil {
		m.Close()
		return nil, err
	}
	if err := attachTP("tp_sys_exit_recvmsg", "syscalls", "sys_exit_recvmsg"); err != nil {
		m.Close()
		return nil, err
	}

	log.Printf("Successfully attached eBPF tracepoint programs for HTTP monitoring")

	// Open ring buffer reader to receive events
	pm, ok := objs.Maps["events"]
	if !ok || pm == nil {
		m.Close()
		return nil, fmt.Errorf("open ringbuf: events map not found in BPF object")
	}
	rb, err := ringbuf.NewReader(pm)
	if err != nil {
		m.Close()
		return nil, fmt.Errorf("open ringbuf reader: %w", err)
	}
	m.reader = rb

	// Optional: debug counters polling
	if os.Getenv("EBPFD_HTTP_DEBUG") != "" {
		if cm, ok := objs.Maps["counters"]; ok && cm != nil {
			log.Printf("EBPFD_HTTP_DEBUG enabled: starting counters poller")
			go func() {
				ncpu := runtime.NumCPU()
				for {
					for i := uint32(0); i < 12; i++ {
						key := i
						vals := make([]uint64, ncpu)
						if err := cm.Lookup(key, &vals); err == nil {
							var sum uint64
							for _, v := range vals {
								sum += v
							}
							name := ""
							switch i {
							case 0:
								name = "TOTAL_SEND"
							case 1:
								name = "TOTAL_RECV"
							case 2:
								name = "HTTP_SEND"
							case 3:
								name = "HTTP_RECV"
							case 4:
								name = "ERRORS"
							case 5:
								name = "HTTP_CHECKS"
							case 6:
								name = "HTTP_MATCH"
							case 7:
								name = "READ_FAILS"
							case 8:
								name = "READ_SUCCESS"
							case 9:
								name = "SEND_BUFF_NULL"
							case 10:
								name = "RECV_ARGS_NULL"
							case 11:
								name = "RECV_BUF_NULL"
							}
							log.Printf("COUNTER %-11s = %d", name, sum)
						} else {
							log.Printf("read counter %d error: %v", i, err)
						}
					}
					time.Sleep(5 * time.Second)
				}
			}()
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel

	// 启动定期清理goroutine
	go m.cleanupCaches(ctx)

	// 启动流清理定时器
	m.flushTicker = time.NewTicker(10 * time.Second)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-m.flushTicker.C:
				// 清理老化的TCP流
				m.streamProcessor.FlushOlderThan(time.Now().Add(-30 * time.Second))
			}
		}
	}()

	go m.loop(ctx, selector)
	return m, nil
}

// 定期清理缓存数据，防止内存泄漏
func (m *HTTPMonitor) cleanupCaches(ctx context.Context) {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.cleanupDone:
			return
		case <-ticker.C:
			m.cleanupExpiredEntries()
		}
	}
}

// 清理过期条目
func (m *HTTPMonitor) cleanupExpiredEntries() {
	now := time.Now()

	// 清理dedup缓存
	m.dedupMutex.Lock()
	dedupCount := len(m.dedup)
	if dedupCount > maxDedupEntries {
		// 如果超过限制，清空重建
		m.dedup = make(map[string]dedupEntry, 128)
		log.Printf("dedup cache exceeded limit (%d), cleared all entries", maxDedupEntries)
	} else {
		// 清理过期条目（5秒TTL）
		const dedupTTL = 5 * time.Second
		for k, ent := range m.dedup {
			if now.Sub(ent.ts) > dedupTTL {
				delete(m.dedup, k)
			}
		}
	}
	m.dedupMutex.Unlock()

	// 清理spliceBuffer缓存
	m.spliceBufferMutex.Lock()
	spliceCount := len(m.spliceBuffer)
	if spliceCount > maxSpliceBufferEntries {
		// 如果超过限制，清理最旧的一半条目
		var oldestKeys []string
		for k, st := range m.spliceBuffer {
			if now.Sub(st.lastUpdate) > time.Minute {
				oldestKeys = append(oldestKeys, k)
			}
		}
		// 删除过期条目
		for _, k := range oldestKeys {
			delete(m.spliceBuffer, k)
		}
		// 如果仍超过限制，强制清空
		if len(m.spliceBuffer) > maxSpliceBufferEntries {
			m.spliceBuffer = make(map[string]*spliceState)
			log.Printf("splice buffer exceeded limit (%d), cleared all entries", maxSpliceBufferEntries)
		} else if len(oldestKeys) > 0 {
			log.Printf("cleaned %d expired splice buffer entries", len(oldestKeys))
		}
	}
	m.spliceBufferMutex.Unlock()

	if dedupCount > 1000 || spliceCount > 1000 {
		log.Printf("cache cleanup completed: dedup=%d, splice=%d", dedupCount, spliceCount)
	}
}

func (m *HTTPMonitor) loop(ctx context.Context, selector monitor.ProcessSelector) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		record, err := m.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("ringbuf read error: %v", err)
			continue
		}

		// 原始 ringbuf 样本（未经解码）
		if m.rawLog != nil {
			m.rawLog.Printf("[RAW] sample_len=%d sample_hex=%x", len(record.RawSample), record.RawSample)
			m.rawLog.Printf("[RAW_STR] %s", toHumanString(record.RawSample))
		}
		var e httpEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &e); err != nil {
			log.Printf("decode event: %v", err)
			continue
		}

		capLen := int(e.Len)
		if capLen < 0 {
			capLen = 0
		}
		if capLen > len(e.Data) {
			capLen = len(e.Data)
		}
		payload := string(e.Data[:capLen])

		// 事件详细信息（含 Data 全量）
		if m.rawLog != nil {
			comm := string(bytes.TrimRight(e.Comm[:], "\x00"))
			if comm == "http-monitor" {
				continue
			}
			m.rawLog.Printf("[EVT] pid=%d comm=%s fd=%d dir=%d len=%d orig=%d data_len=%d", e.PID, comm, e.FD, e.Direction, e.Len, e.OrigLen, capLen)
			if capLen > 0 {
				m.rawLog.Printf("[DATA_HEX] %x", e.Data[:capLen])
				m.rawLog.Printf("[DATA_STR] %s", toHumanString(e.Data[:capLen]))
			} else {
				m.rawLog.Printf("[DATA_HEX] <empty>")
				m.rawLog.Printf("[DATA_STR] <empty>")
			}
		}

		// 添加调试日志：输出所有接收到的eBPF事件
		comm := string(bytes.TrimRight(e.Comm[:], "\x00"))
		log.Printf("[DEBUG] eBPF Event: PID=%d, Comm=%s, FD=%d, Dir=%d, Len=%d, OrigLen=%d, DataPreview=%q",
			e.PID, comm, e.FD, e.Direction, e.Len, e.OrigLen,
			func() string {
				if capLen > 0 {
					previewLen := capLen
					if previewLen > 50 {
						previewLen = 50
					}
					return string(e.Data[:previewLen])
				}
				return "<empty>"
			}())

		// 将片段交给混合处理器处理
		m.processEventWithHybridArchitecture(e, payload, selector)
	}
}

// processEventWithHybridArchitecture 使用混合架构处理事件
func (m *HTTPMonitor) processEventWithHybridArchitecture(e httpEvent, payload string, selector monitor.ProcessSelector) {
	if m.useStreamProcessor {
		// 使用gopacket流处理器
		m.processWithStreamProcessor(e, payload, selector)
	} else {
		// 使用传统拼接逻辑（降级方案）
		if ready, ev, agg := m.spliceOnEvent(e, payload); ready {
			m.emitEvent(ev, agg, selector)
		}
	}
}

// processWithStreamProcessor 使用gopacket流处理器处理事件
func (m *HTTPMonitor) processWithStreamProcessor(e httpEvent, payload string, selector monitor.ProcessSelector) {
	comm := string(bytes.TrimRight(e.Comm[:], "\x00"))
	pid := int(e.PID)

	// 过滤检查
	if !selector.Match(pid, comm) {
		return
	}

	// 解析网络地址信息
	srcIP, srcPort, dstIP, dstPort := "", 0, "", 0
	if t, ok := m.resolvePIDFD(pid, int(e.FD)); ok {
		srcIP, srcPort = t.lIP, t.lPort
		dstIP, dstPort = t.rIP, t.rPort

		// 更新流上下文信息
		m.streamProcessor.UpdateFlowContext(srcIP, srcPort, dstIP, dstPort, pid, comm, e.FD)
	} else {
		// 无法解析地址，使用默认值
		srcIP, srcPort = "127.0.0.1", 0
		dstIP, dstPort = "127.0.0.1", 0
	}

	// 将eBPF事件转换为标准化事件
	streamEvent := &stream.EBPFEvent{
		PID:       e.PID,
		Comm:      comm,
		Len:       e.Len,
		OrigLen:   e.OrigLen,
		FD:        e.FD,
		Direction: e.Direction,
		Data:      payload,
		SrcIP:     srcIP,
		SrcPort:   srcPort,
		DstIP:     dstIP,
		DstPort:   dstPort,
	}

	// 转换为TCP包并交给流处理器
	packet, err := m.packetConverter.EventToPacket(streamEvent)
	if err != nil {
		log.Printf("Failed to convert event to packet: %v, falling back to legacy processing", err)
		// 降级到传统处理
		if ready, ev, agg := m.spliceOnEvent(e, payload); ready {
			m.emitEvent(ev, agg, selector)
		}
		return
	}

	// 交给gopacket流处理器处理
	m.streamProcessor.ProcessPacket(packet)

	// 立即触发流重组，不等待超时
	// 这样可以立即处理数据包，而不是等待FlushOlderThan超时
	m.streamProcessor.FlushOlderThan(time.Now())
}

// 拼接参数
const (
	spliceMaxSize  = 16 * 1024               // 最大聚合输出 16KB
	spliceIdleTTL  = 400 * time.Millisecond  // 空闲超时刷新
	spliceTotalTTL = 1500 * time.Millisecond // 最长等待

	// 缓存预分配大小
	initialBufferSize = 2 * 1024 // 初始缓存大小 2KB
	growthIncrement   = 1 * 1024 // 扩容增量 1KB
)

func makeSpliceKey(pid int, fd int32, dir uint8) string {
	// dir: 0=send,1=recv
	return fmt.Sprintf("%d:%d:%d", pid, int(fd), int(dir))
}

func headerEndIndex(s string) int {
	return strings.Index(s, "\r\n\r\n")
}

func parseContentLength(hs string) (int, bool) {
	// 从 header 文本中找到 Content-Length
	// 不区分大小写
	scanner := bufio.NewScanner(strings.NewReader(hs))
	for scanner.Scan() {
		line := scanner.Text()
		i := strings.Index(line, ":")
		if i <= 0 {
			continue
		}
		k := strings.TrimSpace(line[:i])
		v := strings.TrimSpace(line[i+1:])
		if strings.EqualFold(k, "Content-Length") {
			if n, err := strconv.Atoi(v); err == nil && n >= 0 {
				return n, true
			}
		}
		if strings.TrimSpace(line) == "" { // 防御
			break
		}
	}
	return 0, false
}

func hasChunked(hs string) bool {
	scanner := bufio.NewScanner(strings.NewReader(hs))
	for scanner.Scan() {
		line := scanner.Text()
		i := strings.Index(line, ":")
		if i <= 0 {
			continue
		}
		k := strings.TrimSpace(line[:i])
		v := strings.TrimSpace(line[i+1:])
		if strings.EqualFold(k, "Transfer-Encoding") && strings.Contains(strings.ToLower(v), "chunked") {
			return true
		}
	}
	return false
}

func chunkedComplete(full string, bodyStart int) bool {
	if bodyStart <= 0 || bodyStart >= len(full) {
		return false
	}
	body := full[bodyStart:]
	// 简单判定：出现 CRLF 0 CRLF CRLF 即认为结束
	if strings.Contains(body, "\r\n0\r\n\r\n") {
		return true
	}
	return false
}

// 将事件写入拼接缓冲；若达到输出条件，则返回聚合后的事件与负载
func (m *HTTPMonitor) spliceOnEvent(e httpEvent, payload string) (ready bool, out httpEvent, outPayload string) {
	now := time.Now()

	// 先对所有条目做一次过期检查（避免旧条目一直占用）
	// 注意：不能在这里直接 return，否则会丢弃当前事件
	var expiredReady bool
	var expiredEv httpEvent
	var expiredPayload string

	m.spliceBufferMutex.Lock()
	for k, st := range m.spliceBuffer {
		// 避免在已知需要更多 body（有 CL 且未达标，或 chunked 未结束）情况下因空闲超时提前刷新仅 header
		inProgressBody := false
		if idx := headerEndIndex(st.payload.String()); idx >= 0 {
			if st.isChunked {
				// chunked：未检测到终止块则视为进行中
				if !chunkedComplete(st.payload.String(), idx+4) {
					inProgressBody = true
				}
			} else if st.expectedLen > 0 && st.payload.Len() < st.expectedLen {
				inProgressBody = true
			}
		}

		idleExpired := now.Sub(st.lastUpdate) > spliceIdleTTL
		totalExpired := now.Sub(st.firstEventTs()) > spliceTotalTTL
		sizeExceeded := st.payload.Len() >= spliceMaxSize

		// 对于进行中的响应体（inProgressBody），不因空闲超时而过期，但仍受总 TTL 与大小限制
		if (idleExpired && !inProgressBody) || totalExpired || sizeExceeded {
			s := st.payload.String()
			// 删除旧条目
			delete(m.spliceBuffer, k)
			if !expiredReady && s != "" {
				ev := st.firstEvent
				ev.Len = uint32(len(s))
				ev.OrigLen = uint32(st.origTotal)
				expiredReady = true
				expiredEv = ev
				expiredPayload = s
			}
		}
	}
	m.spliceBufferMutex.Unlock()

	key := makeSpliceKey(int(e.PID), e.FD, e.Direction)
	m.spliceBufferMutex.Lock()
	st, ok := m.spliceBuffer[key]
	if !ok {
		st = &spliceState{firstEvent: e, lastUpdate: now}
		// 第一片也计入 origTotal
		st.origTotal += int(e.OrigLen)
		// 预分配缓存大小，避免频繁重新分配
		initialSize := initialBufferSize
		if len(payload) > initialSize {
			initialSize = len(payload) + growthIncrement
		}
		st.payload.Grow(initialSize)
		st.payload.WriteString(payload)
		// 默认根据方向判定：recv 视为响应，send 视为请求
		st.isResponse = (e.Direction != 0)
		// 若负载以 HTTP 起始行开头，则强制识别为响应
		if strings.HasPrefix(st.payload.String(), "HTTP/1.") {
			st.isResponse = true
		}

		// 若已经有完整 header，尝试解析 Content-Length 或是否 chunked
		if idx := headerEndIndex(st.payload.String()); idx >= 0 {
			hs := st.payload.String()[:idx]
			if hasChunked(hs) {
				st.isChunked = true
				// 对 chunked 不设 expectedLen，等待终止块或超时/空闲
			} else if cl, ok := parseContentLength(hs); ok {
				st.expectedLen = idx + 4 + cl
			} else {
				// 无 CL 且非 chunked：若是无实体响应(1xx/204/304)，在 header 处立即完成
				if st.isResponse {
					if code, ok := parseStatusCode(hs); ok {
						if (code >= 100 && code < 200) || code == 204 || code == 304 {
							st.expectedLen = idx + 4
						}
					}
				}

				// 对于请求（非响应）且无 CL/非 chunked：认为 header-only
				if !st.isResponse && !st.isChunked && st.expectedLen == 0 {
					st.expectedLen = idx + 4
				}

				// 若为 chunked，检查是否已在本片内结束（0\r\n\r\n）
				if st.isChunked && chunkedComplete(st.payload.String(), idx+4) {
					s := st.payload.String()
					ev := st.firstEvent
					ev.Len = uint32(len(s))
					ev.OrigLen = uint32(st.origTotal)
					return true, ev, s
				}
			}
			// 额外：如果无 CL 且非 chunked，且同一片段内出现下一条响应的起始，则切分
			if st.isResponse && !st.isChunked && st.expectedLen == 0 {
				if cut := strings.Index(st.payload.String()[idx+4:], "\r\nHTTP/1."); cut >= 0 {
					cut += idx + 4
					s := st.payload.String()[:cut]
					ev := st.firstEvent
					ev.Len = uint32(len(s))
					ev.OrigLen = uint32(st.origTotal)
					// 用剩余部分开启新响应
					rest := st.payload.String()[cut+2:]
					ns := &spliceState{firstEvent: e, lastUpdate: now}
					// 预分配缓存
					restSize := len(rest) + growthIncrement
					if restSize < initialBufferSize {
						restSize = initialBufferSize
					}
					ns.payload.Grow(restSize)
					ns.payload.WriteString(rest)
					ns.origTotal += int(e.OrigLen)
					if strings.HasPrefix(ns.payload.String(), "HTTP/1.") {
						ns.isResponse = true
					}
					if idx2 := headerEndIndex(ns.payload.String()); idx2 >= 0 {
						hs2 := ns.payload.String()[:idx2]
						if hasChunked(hs2) {
							ns.isChunked = true
						} else if cl2, ok2 := parseContentLength(hs2); ok2 {
							ns.expectedLen = idx2 + 4 + cl2
						} else if ns.isResponse {
							if code2, ok2 := parseStatusCode(hs2); ok2 {
								if (code2 >= 100 && code2 < 200) || code2 == 204 || code2 == 304 {
									ns.expectedLen = idx2 + 4
								}
							}
						}
					}
					m.spliceBuffer[key] = ns
					return true, ev, s
				}
			}
		}
		m.spliceBuffer[key] = st
		// 若第一片即足够（如仅 header 或 header+body 足量），直接输出
		if (!st.isChunked && st.expectedLen > 0 && st.payload.Len() >= st.expectedLen) || st.payload.Len() >= spliceMaxSize {
			s := st.payload.String()
			ev := st.firstEvent
			ev.Len = uint32(len(s))
			ev.OrigLen = uint32(st.origTotal)
			delete(m.spliceBuffer, key)
			m.spliceBufferMutex.Unlock()
			return true, ev, s
		}
		m.spliceBufferMutex.Unlock()
		// 当前事件尚不能输出，如有过期条目需要输出，则先输出过期条目
		if expiredReady {
			return true, expiredEv, expiredPayload
		}
		return false, httpEvent{}, ""
	}
	m.spliceBufferMutex.Unlock()

	// 边界探测：上一条为未知长度响应，且新片段疑似以新响应起始
	m.spliceBufferMutex.Lock()
	if st.isResponse && st.expectedLen == 0 && !st.isChunked {

		// 跨片段边界：上一片以 "\r" 结尾，当前片以 "\nHTTP/" 开头
		if strings.HasPrefix(payload, "\nHTTP/1.") && strings.HasSuffix(st.payload.String(), "\r") {
			// 完成旧响应并输出
			s := st.payload.String()
			ev := st.firstEvent
			ev.Len = uint32(len(s))
			ev.OrigLen = uint32(st.origTotal)
			// 用去掉前导 \n 的剩余部分开启新响应
			rest := payload[1:]
			ns := &spliceState{firstEvent: e, lastUpdate: now}
			// 预分配缓存
			restSize := len(rest) + growthIncrement
			if restSize < initialBufferSize {
				restSize = initialBufferSize
			}
			ns.payload.Grow(restSize)
			ns.payload.WriteString(rest)
			ns.origTotal += int(e.OrigLen)
			// 默认根据方向判定，再依据起始行覆盖
			ns.isResponse = (e.Direction != 0)
			ns.isResponse = true
			if idx := headerEndIndex(ns.payload.String()); idx >= 0 {
				hs := ns.payload.String()[:idx]
				if hasChunked(hs) {
					ns.isChunked = true
				} else if cl, ok := parseContentLength(hs); ok {
					ns.expectedLen = idx + 4 + cl
				} else {
					if code, ok := parseStatusCode(hs); ok {
						if (code >= 100 && code < 200) || code == 204 || code == 304 {
							ns.expectedLen = idx + 4
						}
					}
				}
			}
			m.spliceBuffer[key] = ns
			m.spliceBufferMutex.Unlock()
			return true, ev, s
		}
		// 如果新片段中包含 "\r\nHTTP/"，视为下一条响应的起始
		if cut := strings.Index(payload, "\r\nHTTP/1."); cut >= 0 {
			// 先把前段 body 追加到旧响应
			if cut > 0 {
				st.payload.WriteString(payload[:cut])
			}
			// 完成旧响应并输出
			s := st.payload.String()
			ev := st.firstEvent
			ev.Len = uint32(len(s))
			ev.OrigLen = uint32(st.origTotal)
			// 用剩余部分开启新响应（应以 HTTP/ 开头）
			rest := payload[cut+2:]
			ns := &spliceState{firstEvent: e, lastUpdate: now}
			// 预分配缓存
			restSize := len(rest) + growthIncrement
			if restSize < initialBufferSize {
				restSize = initialBufferSize
			}
			ns.payload.Grow(restSize)
			ns.payload.WriteString(rest)
			ns.origTotal += int(e.OrigLen)
			// 默认根据方向判定，再依据起始行覆盖
			ns.isResponse = (e.Direction != 0)
			if strings.HasPrefix(ns.payload.String(), "HTTP/1.") {
				ns.isResponse = true
			}
			if idx := headerEndIndex(ns.payload.String()); idx >= 0 {
				hs := ns.payload.String()[:idx]
				if hasChunked(hs) {
					ns.isChunked = true
				} else if cl, ok := parseContentLength(hs); ok {
					ns.expectedLen = idx + 4 + cl
				} else {
					if code, ok := parseStatusCode(hs); ok {
						if (code >= 100 && code < 200) || code == 204 || code == 304 {
							ns.expectedLen = idx + 4
						}
					}
				}
			}
			m.spliceBuffer[key] = ns
			m.spliceBufferMutex.Unlock()
			return true, ev, s
		}
		// 如果整个新片段本身就以 "HTTP/" 开头，也视为新的响应；旧响应立即输出
		if strings.HasPrefix(payload, "HTTP/1.") {
			s := st.payload.String()
			ev := st.firstEvent
			ev.Len = uint32(len(s))
			ev.OrigLen = uint32(st.origTotal)
			ns := &spliceState{firstEvent: e, lastUpdate: now}
			// 预分配缓存
			payloadSize := len(payload) + growthIncrement
			if payloadSize < initialBufferSize {
				payloadSize = initialBufferSize
			}
			ns.payload.Grow(payloadSize)
			ns.payload.WriteString(payload)
			ns.origTotal += int(e.OrigLen)
			// 默认根据方向判定，再依据起始行覆盖
			ns.isResponse = (e.Direction != 0)
			ns.isResponse = true
			if idx := headerEndIndex(ns.payload.String()); idx >= 0 {
				hs := ns.payload.String()[:idx]
				if hasChunked(hs) {
					ns.isChunked = true
				} else if cl, ok := parseContentLength(hs); ok {
					ns.expectedLen = idx + 4 + cl
				} else {
					if code, ok := parseStatusCode(hs); ok {
						if (code >= 100 && code < 200) || code == 204 || code == 304 {
							ns.expectedLen = idx + 4
						}
					}
				}
			}
			m.spliceBuffer[key] = ns
			m.spliceBufferMutex.Unlock()
			return true, ev, s
		}
	}

	st.payload.WriteString(payload)
	st.lastUpdate = now
	st.origTotal += int(e.OrigLen)

	// 若尚未知道 expectedLen，且 header 已结束，尝试解析 CL 或 chunked（并处理请求无体的情形）
	if st.expectedLen == 0 {
		if idx := headerEndIndex(st.payload.String()); idx >= 0 {
			hs := st.payload.String()[:idx]
			if hasChunked(hs) {
				st.isChunked = true
				// 如果 chunked 已在当前累计片段内结束，立即输出
				if chunkedComplete(st.payload.String(), idx+4) {
					s := st.payload.String()
					ev := st.firstEvent
					ev.Len = uint32(len(s))
					ev.OrigLen = uint32(st.origTotal)
					delete(m.spliceBuffer, key)
					m.spliceBufferMutex.Unlock()
					return true, ev, s
				}
			} else if cl, ok := parseContentLength(hs); ok {
				st.expectedLen = idx + 4 + cl
			} else {
				// 无 CL 且非 chunked 的请求：认为无体，按 header 截止
				if !st.isResponse {
					st.expectedLen = idx + 4
				} else {
					// 无实体响应(1xx/204/304)
					if code, ok := parseStatusCode(hs); ok {
						if (code >= 100 && code < 200) || code == 204 || code == 304 {
							st.expectedLen = idx + 4
						}
					}
				}
			}
		}
	}

	// 若达到 expectedLen（非 chunked），或超过最大拼接大小，立即输出
	if (!st.isChunked && st.expectedLen > 0 && st.payload.Len() >= st.expectedLen) || st.payload.Len() >= spliceMaxSize {
		s := st.payload.String()
		ev := st.firstEvent
		ev.Len = uint32(len(s))
		ev.OrigLen = uint32(st.origTotal)
		delete(m.spliceBuffer, key)
		m.spliceBufferMutex.Unlock()
		return true, ev, s
	}
	m.spliceBufferMutex.Unlock()

	// 如有过期条目需要输出，则先输出过期条目
	if expiredReady {
		return true, expiredEv, expiredPayload
	}
	return false, httpEvent{}, ""
}

// 取第一个事件时间（用来计算 total TTL）；为简单起见使用 firstEvent 中的时间不可得，退化为 lastUpdate 初始值
func (st *spliceState) firstEventTs() time.Time {
	return st.lastUpdate // 我们在创建时即赋值为 now
}

// 输出一个事件（构建 JSON，去重等），复用原先 loop 逻辑
func (m *HTTPMonitor) emitEvent(e httpEvent, payload string, selector monitor.ProcessSelector) {
	comm := string(bytes.TrimRight(e.Comm[:], "\x00"))
	pid := int(e.PID)
	if !selector.Match(pid, comm) {
		return
	}

	// Quick debug log
	preview := payload
	if len(preview) > 96 {
		preview = preview[:96] + "..."
	}
	log.Printf("EMIT pid=%d comm=%s fd=%d dir=%d len=%d orig=%d payload=[%q]",
		pid, comm, e.FD, e.Direction, e.Len, e.OrigLen, preview)

	info := parser.ParseHTTP(payload)

	wire := "send"
	if e.Direction != 0 {
		wire = "recv"
	}

	// Resolve addresses
	srcIP, srcPort, dstIP, dstPort := "", 0, "", 0
	if t, ok := m.resolvePIDFD(pid, int(e.FD)); ok {
		srcIP, srcPort = t.lIP, t.lPort
		dstIP, dstPort = t.rIP, t.rPort
	}

	// de-dup（仅对响应方向做）
	if wire == "recv" && info.Direction == "response" {
		now := time.Now()
		startLine := info.Headers[":start-line"]
		cl := info.Headers["Content-Length"]
		host := info.Headers["Host"]
		key := fmt.Sprintf("%s|%d|%s|%s|%s|%s", wire, pid, comm, startLine, host, cl)

		m.dedupMutex.Lock()
		bodyLen := len(info.Body)
		if ent, ok := m.dedup[key]; ok {
			if bodyLen == 0 || bodyLen <= ent.bestLen {
				m.dedupMutex.Unlock()
				log.Printf("de-dup drop: pid=%d comm=%s start=%q CL=%s oldBest=%d new=%d", pid, comm, startLine, cl, ent.bestLen, bodyLen)
				return
			}
		}
		m.dedup[key] = dedupEntry{bestLen: bodyLen, ts: now}
		m.dedupMutex.Unlock()
	}

	output := map[string]interface{}{
		"time":    time.Now().UnixMilli(),
		"pid":     pid,
		"comm":    comm,
		"wire":    wire,
		"len":     int(e.Len),
		"origLen": int(e.OrigLen),
		"fd":      int(e.FD),
		"srcIP":   srcIP,
		"srcPort": srcPort,
		"dstIP":   dstIP,
		"dstPort": dstPort,
		"http": map[string]interface{}{
			"direction": info.Direction,
			"headers":   info.Headers,
			"body":      info.Body,
		},
	}
	if m.OnEvent != nil {
		if data, err := json.Marshal(output); err == nil {
			m.OnEvent(data)
		}
	}
}

func preferIPv4Text(s string) string {
	if s == "" {
		return s
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return s
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String()
	}
	return ip.String()
}

// 将字节序列转换为可读字符串：
// - 可打印 ASCII (32..126) 原样保留
// - 换行/回车/制表符转义为 \n/\r/\t
// - 其他不可见字符统一映射为 '.'
func toHumanString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.Grow(len(b))
	for _, c := range b {
		switch c {
		case '\r':
			sb.WriteString("\\r")
		case '\n':
			sb.WriteString("\\n")
		case '\t':
			sb.WriteString("\\t")
		default:
			if c >= 32 && c < 127 {
				sb.WriteByte(c)
			} else {
				sb.WriteByte('.')
			}
		}
	}
	return sb.String()
}

// 解析响应状态码
func parseStatusCode(hs string) (int, bool) {
	scanner := bufio.NewScanner(strings.NewReader(hs))
	if scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "HTTP/") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				if code, err := strconv.Atoi(parts[1]); err == nil {
					return code, true
				}
			}
		}
	}
	return 0, false
}
