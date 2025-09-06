//go:build linux

package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"strings"
	"syscall"
	"time"
)

type RawCapture struct {
	sockfd     int
	targetPort int
	targetPID  int
}

func NewRawCapture(targetPort int, targetPID int) (*RawCapture, error) {
	// 创建原始socket
	sockfd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("创建原始socket失败: %v", err)
	}

	return &RawCapture{
		sockfd:     sockfd,
		targetPort: targetPort,
		targetPID:  targetPID,
	}, nil
}

func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

func (rc *RawCapture) Start() {
	defer syscall.Close(rc.sockfd)

	log.Printf("开始原始socket监控端口 %d 的网络包...", rc.targetPort)
	buffer := make([]byte, 65536)

	for {
		n, _, err := syscall.Recvfrom(rc.sockfd, buffer, 0)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			log.Printf("接收数据错误: %v", err)
			continue
		}

		if n > 14 { // 至少有以太网头
			rc.processPacket(buffer[:n])
		}
	}
}

func (rc *RawCapture) processPacket(packet []byte) {
	// 跳过以太网头（14字节）
	if len(packet) < 14 {
		return
	}

	// 检查是否是IP包
	if packet[12] != 0x08 || packet[13] != 0x00 {
		return
	}

	ipPacket := packet[14:]
	if len(ipPacket) < 20 {
		return
	}

	// 检查是否是TCP
	if ipPacket[9] != 6 {
		return
	}

	// 获取IP头长度
	ipHeaderLen := int(ipPacket[0]&0x0F) * 4
	if len(ipPacket) < ipHeaderLen+20 {
		return
	}

	tcpPacket := ipPacket[ipHeaderLen:]
	if len(tcpPacket) < 20 {
		return
	}

	// 解析TCP端口
	srcPort := binary.BigEndian.Uint16(tcpPacket[0:2])
	dstPort := binary.BigEndian.Uint16(tcpPacket[2:4])

	// 检查是否是目标端口
	if int(srcPort) != rc.targetPort && int(dstPort) != rc.targetPort {
		return
	}

	// 获取TCP头长度
	tcpHeaderLen := int(tcpPacket[12]>>4) * 4
	if len(tcpPacket) < tcpHeaderLen {
		return
	}

	// 获取TCP载荷
	payload := tcpPacket[tcpHeaderLen:]
	if len(payload) == 0 {
		return
	}

	// 检查是否是我们感兴趣的数据大小（334字节左右）
	if len(payload) >= 50 && len(payload) <= 2000 {
		log.Printf("=== 捕获到可能的HTTP响应包 ===")
		log.Printf("时间: %v", time.Now())
		log.Printf("长度: %d 字节", len(payload))
		log.Printf("TCP端口: %d -> %d", srcPort, dstPort)

		// 尝试解析为HTTP响应
		payloadStr := string(payload)
		if strings.Contains(payloadStr, "HTTP/") || strings.Contains(payloadStr, "Content-Type") ||
			strings.Contains(payloadStr, "json") || strings.Contains(payloadStr, "took") {
			log.Printf("HTTP响应内容:")
			log.Printf("%s", payloadStr)
		} else {
			// 尝试查找可打印的部分
			printable := extractPrintableContent(payload)
			if len(printable) > 10 {
				log.Printf("可打印内容: %q", printable[:min(200, len(printable))])
			}

			// 显示十六进制的前部分
			log.Printf("十六进制前64字节: %x", payload[:min(64, len(payload))])
		}
		log.Printf("=== 包捕获结束 ===")
	}
}

func extractPrintableContent(data []byte) string {
	var result strings.Builder
	for _, b := range data {
		if b >= 32 && b <= 126 { // 可打印ASCII字符
			result.WriteByte(b)
		} else if b == 10 || b == 13 { // 换行符
			result.WriteByte(' ')
		}
	}
	return result.String()
}

func startPacketCapture() {
	// 检查是否有权限创建原始socket
	if syscall.Getuid() != 0 {
		log.Printf("警告: 需要root权限进行网络包捕获")
		return
	}

	// 启动原始socket捕获 (监控端口9200)
	rc, err := NewRawCapture(9200, TargetPID)
	if err != nil {
		log.Printf("警告: 无法启动网络包捕获: %v", err)
		return
	}

	go func() {
		// 延迟启动，等待eBPF程序先运行
		time.Sleep(2 * time.Second)
		log.Printf("网络包捕获已启动...")
		rc.Start()
	}()
}
