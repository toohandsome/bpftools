// Package main - Redis增强监控主程序
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/myserver/go-server/ebpf/middle/monitor"
	"github.com/myserver/go-server/ebpf/middle/types"
)

func main() {
	var (
		iface   = flag.String("interface", "", "网络接口名称 (如: eth0, wlan0)")
		host    = flag.String("host", "127.0.0.1", "Redis主机地址")
		port    = flag.Int("port", 6379, "Redis端口号")
		verbose = flag.Bool("verbose", false, "详细输出")
		snaplen = flag.Int("snaplen", 65536, "抓包长度")
		timeout = flag.Duration("timeout", 30*time.Second, "读取超时")
		promisc = flag.Bool("promisc", false, "混杂模式")
	)
	flag.Parse()

	if *iface == "" {
		fmt.Println("Redis增强监控器 - 支持请求响应关联和数据库跟踪")
		fmt.Println()
		fmt.Println("使用方法:")
		fmt.Println("  -interface string    网络接口名称 (必需)")
		fmt.Println("  -host string         Redis主机地址 (默认: 127.0.0.1)")
		fmt.Println("  -port int            Redis端口号 (默认: 6379)")
		fmt.Println("  -verbose             详细输出")
		fmt.Println("  -snaplen int         抓包长度 (默认: 65536)")
		fmt.Println("  -timeout duration    读取超时 (默认: 30s)")
		fmt.Println("  -promisc             混杂模式 (默认: false)")
		fmt.Println()
		fmt.Println("示例:")
		fmt.Println("  sudo go run redis_enhanced_main.go -interface eth0")
		fmt.Println("  sudo go run redis_enhanced_main.go -interface eth0 -port 6380 -verbose")
		fmt.Println()
		fmt.Println("输出格式:")
		fmt.Println("  HH:MM:SS.mmm db=X cmd=命令 key=键名 req=请求内容 resp=响应内容 cost=耗时μs")
		os.Exit(1)
	}

	fmt.Printf("🚀 启动Redis增强监控器...\n")
	fmt.Printf("接口: %s\n", *iface)
	fmt.Printf("目标: %s:%d\n", *host, *port)
	fmt.Printf("详细模式: %v\n", *verbose)

	// 创建Redis监控器
	redisMonitor := monitor.NewRedisMonitor(*verbose)

	// 启动监控
	if err := redisMonitor.Start(); err != nil {
		log.Fatalf("启动Redis监控器失败: %v", err)
	}
	defer redisMonitor.Stop()

	// 打开网络接口
	handle, err := pcap.OpenLive(*iface, int32(*snaplen), *promisc, *timeout)
	if err != nil {
		log.Fatalf("打开网络接口失败: %v", err)
	}
	defer handle.Close()

	// 设置过滤器
	filter := fmt.Sprintf("tcp and host %s and port %d", *host, *port)
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatalf("设置BPF过滤器失败: %v", err)
	}

	if *verbose {
		log.Printf("📡 BPF过滤器: %s", filter)
	}

	// 创建上下文
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 信号处理
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// 启动包处理
	packetChan := make(chan gopacket.Packet, 1000)
	go capturePackets(handle, packetChan, ctx)

	// 连接状态跟踪
	connections := make(map[string]*types.Connection)

	fmt.Printf("✅ 监控已启动，等待Redis流量...\n")
	if !*verbose {
		fmt.Printf("💡 使用 -verbose 查看详细日志\n")
	}
	fmt.Printf("🛑 按 Ctrl+C 停止监控\n\n")

	// 主循环
	for {
		select {
		case <-sigChan:
			fmt.Printf("\n🛑 接收到停止信号，正在停止监控...\n")
			cancel()
			return

		case packet := <-packetChan:
			if packet == nil {
				continue
			}

			// 处理数据包
			if err := processPacket(packet, redisMonitor, connections, *host, *port, *verbose); err != nil {
				if *verbose {
					log.Printf("处理数据包失败: %v", err)
				}
			}

		case <-ctx.Done():
			return
		}
	}
}

// capturePackets 捕获数据包
func capturePackets(handle *pcap.Handle, packetChan chan<- gopacket.Packet, ctx context.Context) {
	defer close(packetChan)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case <-ctx.Done():
			return
		default:
			packet, err := packetSource.NextPacket()
			if err != nil {
				continue
			}
			select {
			case packetChan <- packet:
			case <-ctx.Done():
				return
			}
		}
	}
}

// processPacket 处理数据包
func processPacket(packet gopacket.Packet, redisMonitor *monitor.RedisMonitor,
	connections map[string]*types.Connection, targetHost string, targetPort int, verbose bool) error {

	// 解析TCP层
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil
	}
	tcp := tcpLayer.(*layers.TCP)

	// 解析IP层
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil
	}
	ip := ipLayer.(*layers.IPv4)

	// 获取应用数据
	payload := tcp.Payload
	if len(payload) == 0 {
		return nil
	}

	// 确定连接信息
	srcAddr := fmt.Sprintf("%s:%d", ip.SrcIP, tcp.SrcPort)
	dstAddr := fmt.Sprintf("%s:%d", ip.DstIP, tcp.DstPort)

	// 检查是否是目标Redis连接
	isRedisConnection := false
	var direction types.ConnectionDirection

	targetAddr := fmt.Sprintf("%s:%d", targetHost, targetPort)

	if srcAddr == targetAddr {
		// 从Redis服务器发出的数据 (响应)
		isRedisConnection = true
		direction = types.DirectionOutbound
	} else if dstAddr == targetAddr {
		// 发往Redis服务器的数据 (请求)
		isRedisConnection = true
		direction = types.DirectionInbound
	}

	if !isRedisConnection {
		return nil
	}

	// 生成连接键
	connKey := fmt.Sprintf("%s->%s", srcAddr, dstAddr)

	// 获取或创建连接信息
	conn, exists := connections[connKey]
	if !exists {
		conn = &types.Connection{
			LocalAddr:  dstAddr,
			RemoteAddr: srcAddr,
			Direction:  direction,
			StartTime:  time.Now(),
		}
		connections[connKey] = conn

		if verbose {
			log.Printf("🔗 新连接: %s (方向: %s)", connKey, direction)
		}
	}

	// 处理Redis协议数据
	if err := redisMonitor.ProcessPacket(payload, conn); err != nil {
		if verbose {
			log.Printf("处理Redis数据包失败: %v", err)
		}
	}

	return nil
}
