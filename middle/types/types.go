// Package types 定义中间件监控的核心数据结构
package types

import (
	"net"
	"time"
)

// ConnectionDirection 连接方向
type ConnectionDirection int

const (
	DirectionInbound  ConnectionDirection = iota // 入站（服务端接收）
	DirectionOutbound                            // 出站（客户端发送）
	DirectionUnknown                             // 未知方向
)

func (d ConnectionDirection) String() string {
	switch d {
	case DirectionInbound:
		return "inbound"
	case DirectionOutbound:
		return "outbound"
	default:
		return "unknown"
	}
}

// Connection 连接信息
type Connection struct {
	LocalAddr  string              // 本地地址
	RemoteAddr string              // 远程地址
	Direction  ConnectionDirection // 连接方向
	StartTime  time.Time           // 连接开始时间
}

// Message 通用消息结构
type Message struct {
	ID         string      // 消息ID（用于请求响应匹配）
	Type       string      // 消息类型 (request/response)
	Command    string      // 命令/操作名称
	Data       []byte      // 原始数据
	ParsedData any         // 解析后的数据
	Timestamp  time.Time   // 时间戳
	Connection *Connection // 连接信息
	Size       int         // 数据大小
}

// RequestResponse 请求响应对
type RequestResponse struct {
	Request    *Message      // 请求消息
	Response   *Message      // 响应消息
	Duration   time.Duration // 耗时
	Success    bool          // 是否成功
	ErrorMsg   string        // 错误信息
	Connection *Connection   // 连接信息
}

// Stats 统计信息
type Stats struct {
	TotalRequests     int64         // 总请求数
	TotalResponses    int64         // 总响应数
	SuccessCount      int64         // 成功数量
	ErrorCount        int64         // 错误数量
	AvgLatency        time.Duration // 平均延迟
	MaxLatency        time.Duration // 最大延迟
	MinLatency        time.Duration // 最小延迟
	BytesReceived     int64         // 接收字节数
	BytesSent         int64         // 发送字节数
	ActiveConnections int           // 活跃连接数
	StartTime         time.Time     // 统计开始时间
}

// 协议解析器接口
type ProtocolParser interface {
	//  解析请求
	ParseRequest(data []byte) (*Message, error)

	//  解析响应
	ParseResponse(data []byte) (*Message, error)

	//  判断是否为请求
	IsRequest(data []byte) bool

	//  判断是否为响应
	IsResponse(data []byte) bool

	//  获取协议名称
	GetProtocol() string

	//  获取默认端口
	GetDefaultPort() int
}

// Monitor 监控器接口
type Monitor interface {
	// Start 启动监控
	Start() error

	// Stop 停止监控
	Stop() error

	// GetStats 获取统计信息
	GetStats() *Stats

	// SetCallback 设置回调函数
	SetCallback(callback func(*RequestResponse))
}

// PacketInfo 数据包信息
type PacketInfo struct {
	Timestamp   time.Time           // 时间戳
	SrcIP       net.IP              // 源IP
	DstIP       net.IP              // 目标IP
	SrcPort     int                 // 源端口
	DstPort     int                 // 目标端口
	Data        []byte              // 数据内容
	Direction   ConnectionDirection // 方向
	TCPFlags    uint8               // TCP标志位
	SeqNum      uint32              // TCP序列号
	AckNum      uint32              // TCP确认号
	PayloadSize int                 // 负载大小
}
