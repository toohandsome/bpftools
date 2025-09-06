//go:build linux
// +build linux

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

type RawCapture struct {
	sockfd     int
	targetPort int
}

func NewRawCapture(targetPort int) (*RawCapture, error) {
	// 创建原始socket - 关键修复：直接使用ETH_P_ALL，无需htons
	sockfd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(syscall.ETH_P_ALL))
	if err != nil {
		return nil, fmt.Errorf("创建原始socket失败: %v", err)
	}

	// 设置接收超时，避免永久阻塞
	tv := syscall.Timeval{
		Sec:  1, // 1秒超时
		Usec: 0,
	}
	if err := syscall.SetsockoptTimeval(sockfd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		syscall.Close(sockfd)
		return nil, fmt.Errorf("设置socket超时失败: %v", err)
	}

	// 添加内核级BPF过滤（性能关键！）
	if err := setSocketFilter(sockfd, targetPort); err != nil {
		syscall.Close(sockfd)
		return nil, fmt.Errorf("设置BPF过滤器失败: %v", err)
	}

	return &RawCapture{
		sockfd:     sockfd,
		targetPort: targetPort,
	}, nil
}

// 设置内核级BPF过滤器，只接收目标端口的TCP包
func setSocketFilter(sockfd int, port int) error {
	// BPF指令：过滤目标或源端口为指定端口的TCP包
	// tcp dst port XXXX or tcp src port XXXX
	filter := []syscall.SockFilter{
		// 验证IP包 (跳过以太网头14字节)
		{0x28, 0, 0, 0x0000000c}, // ldh [12]
		{0x15, 0, 8, 0x00000800}, // jeq #0x800, pass, next
		// 验证IP协议为TCP (协议字段在IP头偏移9)
		{0x30, 0, 0, 0x00000017}, // ldb [23]
		{0x15, 2, 0, 0x00000006}, // jeq #6, pass, next
		// 加载目标端口 (IP头长度+TCP头前2字节)
		{0x28, 0, 0, 0x00000014}, // ldh [20]
		{0x45, 8, 0, 0x00001fff}, // jset #0x1fff, next, pass
		{0xb1, 0, 0, 0x0000000e}, // ldh [14]
		{0x48, 0, 0, 0x00000010}, // ldh [16]
		// 检查目标端口
		{0x15, 0, 6, uint32(htons(uint16(port)))}, // jeq #port, accept, next
		// 检查源端口
		{0x48, 0, 0, 0x0000000e},                  // ldh [14]
		{0x15, 3, 0, uint32(htons(uint16(port)))}, // jeq #port, accept, next
		// 拒绝
		{0x6, 0, 0, 0x00000000}, // ret #0
		// 接受
		{0x6, 0, 0, 0x0000ffff}, // ret #65535
	}

	prog := syscall.SockFprog{
		Len:    uint16(len(filter)),
		Filter: (*syscall.SockFilter)(unsafe.Pointer(&filter[0])),
	}

	// 设置BPF过滤器
	_, _, errno := syscall.Syscall(syscall.SYS_SETSOCKOPT, uintptr(sockfd),
		syscall.SOL_SOCKET, syscall.SO_ATTACH_FILTER,
		uintptr(unsafe.Pointer(&prog)), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// 网络字节序转换（主机到网络短整型）
func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

func (rc *RawCapture) Start() {
	defer syscall.Close(rc.sockfd)
	log.Printf("开始监控端口 %d 的网络流量...", rc.targetPort)

	// 使用sync.Pool减少GC压力
	bufferPool := sync.Pool{
		New: func() interface{} {
			b := make([]byte, 65536)
			return &b
		},
	}

	packetCount := 0
	startTime := time.Now()

	for {
		buf := bufferPool.Get().(*[]byte)
		n, _, err := syscall.Recvfrom(rc.sockfd, *buf, 0)

		// 处理超时（正常情况）
		if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
			// 每5秒输出状态
			if time.Since(startTime) > 5*time.Second {
				log.Printf("监控中... 已捕获 %d 个数据包", packetCount)
				startTime = time.Now()
				packetCount = 0
			}
			bufferPool.Put(buf)
			continue
		}

		// 处理中断
		if err == syscall.EINTR {
			bufferPool.Put(buf)
			continue
		}

		// 其他错误
		if err != nil {
			log.Printf("接收数据错误: %v", err)
			bufferPool.Put(buf)
			continue
		}

		packetCount++
		if n > 14 { // 至少有以太网头
			rc.processPacket((*buf)[:n])
		}

		bufferPool.Put(buf)

		// 流量控制：防止CPU过载
		if packetCount%1000 == 0 {
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func (rc *RawCapture) processPacket(packet []byte) {
	// 检查IP包 (0x0800)
	if len(packet) < 14 || packet[12] != 0x08 || packet[13] != 0x00 {
		return
	}

	ipPacket := packet[14:]
	if len(ipPacket) < 20 {
		return
	}

	// 检查是否是TCP (协议6)
	if ipPacket[9] != 6 {
		return
	}

	// 获取IP头长度 (确保在有效范围内)
	ipHeaderLen := int(ipPacket[0]&0x0F) * 4
	if ipHeaderLen < 20 || ipHeaderLen > 60 || len(ipPacket) < ipHeaderLen {
		return
	}

	tcpPacket := ipPacket[ipHeaderLen:]
	if len(tcpPacket) < 20 {
		return
	}

	// 解析TCP端口
	srcPort := binary.BigEndian.Uint16(tcpPacket[0:2])
	dstPort := binary.BigEndian.Uint16(tcpPacket[2:4])

	// 检查是否是目标端口 (BPF已过滤，这里双重确认)
	if int(srcPort) != rc.targetPort && int(dstPort) != rc.targetPort {
		return
	}

	// 获取TCP头长度
	tcpHeaderLen := int(tcpPacket[12]>>4) * 4
	if tcpHeaderLen < 20 || len(tcpPacket) < tcpHeaderLen {
		return
	}

	// 获取TCP载荷
	payload := tcpPacket[tcpHeaderLen:]
	if len(payload) == 0 {
		return
	}

	// 优化：只处理合理大小的HTTP响应
	if len(payload) < 50 || len(payload) > 2000 {
		return
	}

	// 检查是否是HTTP响应 (使用bytes操作，避免字符串转换)
	if !isHTTPResponse(payload) {
		return
	}

	log.Printf("=== 捕获到HTTP响应包 ===")
	log.Printf("时间: %v", time.Now())
	log.Printf("长度: %d 字节", len(payload))
	log.Printf("TCP端口: %d -> %d", srcPort, dstPort)

	// 安全处理：限制日志输出大小
	maxLogSize := 500
	if len(payload) < maxLogSize {
		maxLogSize = len(payload)
	}

	// 尝试提取可读内容
	printable := extractPrintableContent(payload[:maxLogSize])
	if len(printable) > 0 {
		log.Printf("可读内容: %q", printable)
	}

	// 显示十六进制摘要
	log.Printf("十六进制摘要: % x", payload[:min(64, len(payload))])
	log.Printf("=== 包捕获结束 ===")
}

// 检查是否是HTTP响应
func isHTTPResponse(payload []byte) bool {
	// 检查"HTTP/"前缀（更可靠）
	if len(payload) > 5 && bytes.Equal(payload[:5], []byte("HTTP/")) {
		return true
	}
	// 检查常见HTTP头
	return bytes.Contains(payload, []byte("Content-Type")) ||
		bytes.Contains(payload, []byte("content-length"))
}

// 提取可打印内容（优化版）
func extractPrintableContent(data []byte) string {
	var result strings.Builder
	for i, b := range data {
		// 限制提取长度，避免大日志
		if i >= 200 {
			break
		}
		if b >= 32 && b <= 126 { // 可打印ASCII字符
			result.WriteByte(b)
		} else if b == '\n' || b == '\r' {
			result.WriteByte(' ')
		}
	}
	return result.String()
}

// 辅助函数
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// 启动包捕获
func startPacketCapture(targetPort int) {
	// 检查网络捕获权限
	if err := checkCapturePermissions(); err != nil {
		log.Printf("错误: %v", err)
		log.Printf("提示: 请使用 'setcap cap_net_raw+ep ./your_binary' 授予必要权限")
		return
	}

	// 启动原始socket捕获
	rc, err := NewRawCapture(targetPort)
	if err != nil {
		log.Printf("无法启动网络包捕获: %v", err)
		return
	}

	log.Printf("网络包捕获已启动，监控端口: %d", targetPort)
	rc.Start()
}

// 检查捕获权限 (比仅检查root更精确)
func checkCapturePermissions() error {
	// 尝试创建原始socket验证权限
	sockfd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(syscall.ETH_P_ALL))
	if err == nil {
		syscall.Close(sockfd)
		return nil
	}

	// 特定错误处理
	if err == syscall.EPERM {
		return fmt.Errorf("权限不足: 需要CAP_NET_RAW能力 (尝试: setcap cap_net_raw+ep ./binary)")
	}
	return fmt.Errorf("无法创建原始socket: %v", err)
}

// 示例用法
func main() {
	// 默认监控Elasticsearch端口
	const defaultPort = 9200

	log.Printf("=== 网络包捕获工具启动 ===")
	log.Printf("监控端口: %d", defaultPort)
	startPacketCapture(defaultPort)
}
