//go:build linux
// +build linux

package stream

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// PacketConverter eBPF事件到TCP包转换器
type PacketConverter struct {
	sequenceNumbers map[string]uint32 // 维护每个流的序列号
}

// NewPacketConverter 创建新的包转换器
func NewPacketConverter() *PacketConverter {
	return &PacketConverter{
		sequenceNumbers: make(map[string]uint32),
	}
}

// EventToPacket 将eBPF事件转换为gopacket格式的TCP包
func (pc *PacketConverter) EventToPacket(event *EBPFEvent) (gopacket.Packet, error) {
	// 验证输入参数
	if event == nil {
		return nil, fmt.Errorf("event is nil")
	}

	// 解析源和目标地址
	srcIP := net.ParseIP(event.SrcIP)
	dstIP := net.ParseIP(event.DstIP)
	if srcIP == nil {
		log.Printf("Invalid source IP: %s", event.SrcIP)
		return nil, fmt.Errorf("invalid source IP: %s", event.SrcIP)
	}
	if dstIP == nil {
		log.Printf("Invalid destination IP: %s", event.DstIP)
		return nil, fmt.Errorf("invalid destination IP: %s", event.DstIP)
	}

	// 验证端口号
	if event.SrcPort < 0 || event.SrcPort > 65535 {
		return nil, fmt.Errorf("invalid source port: %d", event.SrcPort)
	}
	if event.DstPort < 0 || event.DstPort > 65535 {
		return nil, fmt.Errorf("invalid destination port: %d", event.DstPort)
	}

	// 创建以太网层（虚拟）
	ethernetLayer := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x5e, 0x00, 0x53, 0x01}, // 虚拟源MAC
		DstMAC:       net.HardwareAddr{0x00, 0x00, 0x5e, 0x00, 0x53, 0x02}, // 虚拟目标MAC
		EthernetType: layers.EthernetTypeIPv4,
	}
	if srcIP.To4() == nil || dstIP.To4() == nil {
		ethernetLayer.EthernetType = layers.EthernetTypeIPv6
	}

	// 创建IP层
	var networkLayer gopacket.SerializableLayer
	if srcIP.To4() != nil {
		// IPv4
		ipLayer := &layers.IPv4{
			Version:    4,
			IHL:        5,
			TOS:        0,
			Length:     0, // 会被自动计算
			Id:         0,
			Flags:      layers.IPv4DontFragment,
			FragOffset: 0,
			TTL:        64,
			Protocol:   layers.IPProtocolTCP,
			Checksum:   0, // 会被自动计算
			SrcIP:      srcIP.To4(),
			DstIP:      dstIP.To4(),
		}
		networkLayer = ipLayer
	} else {
		// IPv6
		ipLayer := &layers.IPv6{
			Version:      6,
			TrafficClass: 0,
			FlowLabel:    0,
			Length:       0, // 会被自动计算
			NextHeader:   layers.IPProtocolTCP,
			HopLimit:     64,
			SrcIP:        srcIP.To16(),
			DstIP:        dstIP.To16(),
		}
		networkLayer = ipLayer
	}

	// 生成流键用于序列号跟踪
	flowKey := fmt.Sprintf("%s:%d->%s:%d", event.SrcIP, event.SrcPort, event.DstIP, event.DstPort)

	// 获取或初始化序列号
	seq, exists := pc.sequenceNumbers[flowKey]
	if !exists {
		seq = 1000 // 初始序列号
		pc.sequenceNumbers[flowKey] = seq
	}

	// 创建TCP层
	tcpLayer := &layers.TCP{
		SrcPort:    layers.TCPPort(event.SrcPort),
		DstPort:    layers.TCPPort(event.DstPort),
		Seq:        seq,
		Ack:        0,
		DataOffset: 5,
		Window:     65535,
		Checksum:   0, // 会被自动计算
		Urgent:     0,
	}

	// 设置网络层用于校验和计算
	if srcIP.To4() != nil {
		tcpLayer.SetNetworkLayerForChecksum(networkLayer.(*layers.IPv4))
	} else {
		tcpLayer.SetNetworkLayerForChecksum(networkLayer.(*layers.IPv6))
	}

	// 设置TCP标志
	if event.Direction == 0 { // send
		tcpLayer.PSH = true
		tcpLayer.ACK = true
	} else { // recv
		tcpLayer.PSH = true
		tcpLayer.ACK = true
	}

	// 设置负载数据
	payload := []byte(event.Data)

	// 更新序列号
	pc.sequenceNumbers[flowKey] = seq + uint32(len(payload))

	// 创建数据包缓冲区
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// 构建完整的数据包
	var packetLayers []gopacket.SerializableLayer
	packetLayers = append(packetLayers, ethernetLayer)
	packetLayers = append(packetLayers, networkLayer)
	packetLayers = append(packetLayers, tcpLayer)

	// 如果有载荷，添加到层列表中
	if len(payload) > 0 {
		packetLayers = append(packetLayers, gopacket.Payload(payload))
	}

	// 序列化数据包
	err := gopacket.SerializeLayers(buffer, options, packetLayers...)
	if err != nil {
		log.Printf("Failed to serialize layers: %v, event: PID=%d, %s:%d->%s:%d",
			err, event.PID, event.SrcIP, event.SrcPort, event.DstIP, event.DstPort)
		return nil, fmt.Errorf("failed to serialize packet: %v", err)
	}

	// 调试信息
	log.Printf("Successfully created packet: PID=%d, %s:%d->%s:%d, payload_len=%d",
		event.PID, event.SrcIP, event.SrcPort, event.DstIP, event.DstPort, len(payload))

	// 解析生成的数据包
	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	if packet == nil {
		return nil, fmt.Errorf("failed to create packet")
	}

	// 设置时间戳
	packet.Metadata().Timestamp = time.Now()

	return packet, nil
}

// EBPFEvent eBPF事件结构（从现有代码中提取）
type EBPFEvent struct {
	PID       uint32
	Comm      string
	Len       uint32
	OrigLen   uint32
	FD        int32
	Direction uint8 // 0 = send, 1 = recv
	Data      string
	SrcIP     string
	SrcPort   int
	DstIP     string
	DstPort   int
}

// ConvertHTTPEventToEBPFEvent 将现有的HTTP事件转换为标准化的eBPF事件
func ConvertHTTPEventToEBPFEvent(e *HTTPEvent, srcIP string, srcPort int, dstIP string, dstPort int) *EBPFEvent {
	return &EBPFEvent{
		PID:       e.PID,
		Comm:      e.Comm,
		Len:       e.Len,
		OrigLen:   e.OrigLen,
		FD:        e.FD,
		Direction: e.Direction,
		Data:      e.Data,
		SrcIP:     srcIP,
		SrcPort:   srcPort,
		DstIP:     dstIP,
		DstPort:   dstPort,
	}
}

// HTTPEvent 原始HTTP事件结构（与现有代码兼容）
type HTTPEvent struct {
	PID       uint32
	Comm      string
	Len       uint32
	OrigLen   uint32
	FD        int32
	Direction uint8
	Data      string
}

// ParseEndpoint 解析端点字符串为IP和端口
func ParseEndpoint(endpoint string) (string, int, error) {
	parts := strings.Split(endpoint, ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid endpoint format: %s", endpoint)
	}

	ip := parts[0]
	port, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", 0, fmt.Errorf("invalid port: %s", parts[1])
	}

	return ip, port, nil
}

// FlowKey 生成流标识键
func FlowKey(srcIP string, srcPort int, dstIP string, dstPort int) string {
	return fmt.Sprintf("%s:%d->%s:%d", srcIP, srcPort, dstIP, dstPort)
}

// ReverseFlowKey 生成反向流标识键
func ReverseFlowKey(srcIP string, srcPort int, dstIP string, dstPort int) string {
	return fmt.Sprintf("%s:%d->%s:%d", dstIP, dstPort, srcIP, srcPort)
}
