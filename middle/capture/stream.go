// Package capture - TCP流处理器
package capture

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"

	"github.com/myserver/go-server/ebpf/middle/parsers"
	"github.com/myserver/go-server/ebpf/middle/types"
)

// streamFactory TCP流工厂
type streamFactory struct {
	capture *Capture
}

// detectMiddlewareTypeFromConnection 根据端口检测中间件类型
func (factory *streamFactory) detectMiddlewareTypeFromConnection(srcPort, dstPort string) string {
	// 获取所有启用的中间件配置
	enabledMws := factory.capture.config.GetEnabledMiddlewares()

	// 检查源端口和目标端口
	for _, mw := range enabledMws {
		mwPortStr := fmt.Sprintf("%d", mw.Port)
		if srcPort == mwPortStr || dstPort == mwPortStr {
			return mw.Type
		}
	}
	// 未匹配到任何中间件，返回空字符串
	if factory.capture.config.Verbose {
		log.Printf("⚠️ 未匹配到任何中间件，返回空字符串")
	}
	return ""
}

// New 创建新的TCP流
func (factory *streamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	// 解析网络流信息
	srcIP := net.Src()
	dstIP := net.Dst()
	srcPort := transport.Src()
	dstPort := transport.Dst()

	// 判断连接方向（支持多端口）
	direction := types.DirectionUnknown
	var localAddr, remoteAddr string

	// 获取所有目标端口
	allPorts := factory.capture.config.GetAllPorts()
	isTargetSrcPort := false
	isTargetDstPort := false

	// 检查源端口是否为目标端口
	for _, port := range allPorts {
		if srcPort.String() == fmt.Sprintf("%d", port) {
			isTargetSrcPort = true
			break
		}
	}

	// 检查目标端口是否为目标端口
	for _, port := range allPorts {
		if dstPort.String() == fmt.Sprintf("%d", port) {
			isTargetDstPort = true
			break
		}
	}
	// 根据端口判断方向
	if isTargetSrcPort {
		// 源端口是目标端口，说明是从服务器发出的数据（响应）
		direction = types.DirectionInbound
		localAddr = fmt.Sprintf("%s:%s", srcIP.String(), srcPort.String())
		remoteAddr = fmt.Sprintf("%s:%s", dstIP.String(), dstPort.String())
	} else if isTargetDstPort {
		// 目标端口是监控端口，说明是向服务器发送的数据（请求）
		direction = types.DirectionOutbound
		localAddr = fmt.Sprintf("%s:%s", srcIP.String(), srcPort.String())
		remoteAddr = fmt.Sprintf("%s:%s", dstIP.String(), dstPort.String())
	} else {
		// 方向未知
		localAddr = fmt.Sprintf("%s:%s", srcIP.String(), srcPort.String())
		remoteAddr = fmt.Sprintf("%s:%s", dstIP.String(), dstPort.String())
	}

	conn := &types.Connection{
		LocalAddr:  localAddr,
		RemoteAddr: remoteAddr,
		Direction:  direction,
		StartTime:  time.Now(),
	}

	// 根据端口确定中间件类型和解析器
	middlewareType := factory.detectMiddlewareTypeFromConnection(srcPort.String(), dstPort.String())

	// 处理中间件类型为空的情况
	if middlewareType == "" {
		return &tcpreader.ReaderStream{}
	}

	parser := parsers.GetParser(middlewareType)

	// 创建流处理器
	ctx, cancel := context.WithCancel(context.Background())
	stream := &tcpStream{
		factory:        factory,
		connection:     conn,
		reader:         tcpreader.NewReaderStream(),
		buffer:         make([]byte, 0, 64*1024), // 64KB缓冲区
		parser:         parser,
		middlewareType: middlewareType,
		requests:       make(map[string]*types.Message),
		lastActive:     time.Now(),
		ctx:            ctx,
		cancel:         cancel,
	}

	// 启动流处理
	go stream.process()

	// if factory.capture.config.Verbose {
	// 	log.Printf("🌊 创建新TCP流: %s->%s, 方向=%v, 中间件=%s",
	// 		conn.LocalAddr, conn.RemoteAddr, conn.Direction, middlewareType)
	// }

	return &stream.reader
}

// tcpStream TCP流处理器
type tcpStream struct {
	factory        *streamFactory
	connection     *types.Connection
	reader         tcpreader.ReaderStream
	buffer         []byte
	parser         types.ProtocolParser
	middlewareType string // 中间件类型
	requests       map[string]*types.Message
	mu             sync.Mutex
	lastActive     time.Time
	ctx            context.Context
	cancel         context.CancelFunc
}

// process 处理TCP流数据
func (s *tcpStream) process() {
	defer s.reader.Close()
	defer s.cancel() // 确保上下文被取消

	if s.parser == nil {
		log.Printf("未找到 %s 协议解析器", s.middlewareType)
		return
	}

	scanner := bufio.NewScanner(&s.reader)
	scanner.Split(s.splitFunc)

	// 使用带超时的扫描循环避免无限阻塞
	scanTimeout := time.NewTicker(100 * time.Millisecond)
	defer scanTimeout.Stop()

	for {
		select {
		case <-s.ctx.Done():
			if s.factory.capture.config.Verbose {
				log.Printf("TCP流处理器停止: %s -> %s", s.connection.LocalAddr, s.connection.RemoteAddr)
			}
			return
		case <-scanTimeout.C:
			// 检查是否有数据可读
			if scanner.Scan() {
				data := scanner.Bytes()
				if len(data) == 0 {
					continue
				}

				// if s.factory.capture.config.Verbose {
				// 	log.Printf("📦 TCP流接收到数据: 连接=%s->%s, 长度=%d, 时间=%v",
				// 		s.connection.LocalAddr, s.connection.RemoteAddr, len(data), time.Now().Format("15:04:05.000"))
				// }

				s.mu.Lock()
				s.lastActive = time.Now()
				s.processData(data)
				s.mu.Unlock()
			} else {
				// 检查是否有错误
				if err := scanner.Err(); err != nil && err != io.EOF {
					if s.factory.capture.config.Verbose {
						log.Printf("TCP流处理错误: %v", err)
					}
					return
				}
				// 没有数据可读，继续等待
			}
		}
	}
}

// processData 处理数据
func (s *tcpStream) processData(data []byte) {
	// 复制数据到缓冲区
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	if s.factory.capture.config.Verbose {
		maxLen := len(dataCopy)
		if maxLen > 10 {
			maxLen = 10
		}
		// log.Printf("TCP流数据处理: 长度=%d, 前10字节=%v, 连接方向=%v, 数据=%q",
		// 	len(dataCopy), dataCopy[:maxLen], s.connection.Direction, string(dataCopy))
	}

	// 优先根据协议内容判断，而不是连接方向
	isRequest := s.parser.IsRequest(dataCopy)
	isResponse := s.parser.IsResponse(dataCopy)

	// if s.factory.capture.config.Verbose {
	// 	maxPreview := 50
	// 	if len(dataCopy) < maxPreview {
	// 		maxPreview = len(dataCopy)
	// 	}
	// 	log.Printf("🔍 协议分析结果: IsRequest=%v, IsResponse=%v, 数据=%q", isRequest, isResponse, string(dataCopy[:maxPreview]))
	// }

	if isRequest {
		// if s.factory.capture.config.Verbose {
		// 	log.Printf("🔍 检测到请求数据: %q", string(dataCopy))
		// }
		s.handleRequest(dataCopy)
	} else if isResponse {
		// if s.factory.capture.config.Verbose {
		// 	log.Printf("🔍 检测到响应数据: %q", string(dataCopy))
		// }
		s.handleResponse(dataCopy)
	} else {
		if s.factory.capture.config.Verbose {
			// log.Printf("未知数据类型，根据连接方向判断")
		}
		// 备用逻辑：根据连接方向判断
		switch s.connection.Direction {
		case types.DirectionOutbound:
			// 客户端方向，更可能是请求
			s.handleRequest(dataCopy)
		case types.DirectionInbound:
			// 服务端方向，更可能是响应
			s.handleResponse(dataCopy)
		default:
			// 方向未知，尝试解析为请求
			if s.factory.capture.config.Verbose {
				// log.Printf("方向未知，尝试解析为请求")
			}
			s.handleRequest(dataCopy)
		}
	}
}

// handleRequest 处理请求
func (s *tcpStream) handleRequest(data []byte) {
	// 添加原始数据调试
	// if s.factory.capture.config.Verbose {
	// 	maxLen := len(data)
	// 	if maxLen > 100 {
	// 		maxLen = 100
	// 	}
	// 	log.Printf("🔍 处理请求数据: 长度=%d, 数据=%q", len(data), string(data[:maxLen]))
	// }

	msg, err := s.parser.ParseRequest(data)
	if err != nil {
		if s.factory.capture.config.Verbose {
			previewLen := len(data)
			if previewLen > 50 {
				previewLen = 50
			}
			log.Printf("解析请求失败: %v, 数据预览: %s", err, string(data[:previewLen]))
		}
		return
	}

	msg.Connection = s.connection
	msg.Timestamp = time.Now()

	// 添加详细的连接调试信息
	if s.factory.capture.config.Verbose {
		// log.Printf("🔍 请求连接信息: %s -> %s, 方向: %v, 命令: %s, ID: %s",
		// 	msg.Connection.LocalAddr, msg.Connection.RemoteAddr, msg.Connection.Direction, msg.Command, msg.ID)

		// 显示解析的数据
		// if parsedData, ok := msg.ParsedData.([]string); ok {
		// log.Printf("🔍 解析的命令参数: %v", parsedData)
		// }
	}

	// 将请求存储到全局的Capture层面，而不是本地流
	s.factory.capture.storeRequest(msg)

	// if s.factory.capture.config.Verbose {
	// 	log.Printf("📋 存储请求: %s, 连接: %s -> %s, 时间: %v",
	// 		msg.ID, msg.Connection.LocalAddr, msg.Connection.RemoteAddr, msg.Timestamp.Format("15:04:05.000"))
	// }

	// 检查是否有等待的响应需要匹配
	s.factory.capture.checkPendingResponses(msg)

	// 不再立即创建 RequestResponse 对象，等待响应匹配
}

// handleResponse 处理响应
func (s *tcpStream) handleResponse(data []byte) {
	msg, err := s.parser.ParseResponse(data)
	if err != nil {
		if s.factory.capture.config.Verbose {
			previewLen := len(data)
			if previewLen > 50 {
				previewLen = 50
			}
			// log.Printf("解析响应失败: %v, 数据预览: %s", err, string(data[:previewLen]))
		}
		return
	}

	msg.Connection = s.connection
	msg.Timestamp = time.Now()

	// 判断是否为真正的最终响应（简单字符串或错误响应）
	isFinalResponse := s.isFinalResponse(data)
	if !isFinalResponse {
		if s.factory.capture.config.Verbose {
			// log.Printf("跳过中间数据分片: %s", string(data))
		}
		return
	}

	// 使用新的响应缓存机制来处理响应
	s.factory.capture.storeOrMatchResponse(msg)

	// if s.factory.capture.config.Verbose {
	// 	log.Printf("🔍 响应处理: 连接=%s->%s, 时间=%v, 立即匹配=%v",
	// 		msg.Connection.LocalAddr, msg.Connection.RemoteAddr, msg.Timestamp.Format("15:04:05.000"), matched)
	// }
}

// isFinalResponse 判断是否为最终响应（针对Redis）
func (s *tcpStream) isFinalResponse(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	// 对于Redis，只有以下类型才是最终响应：
	// +：简单字符串响应（如+OK\r\n）
	// -：错误响应
	// :：整数响应
	switch data[0] {
	case '+':
		// 简单字符串响应，如+OK\r\n
		return true
	case '-':
		// 错误响应
		return true
	case ':':
		// 整数响应
		return true
	case '$':
		// 批量字符串响应，只有完整的才算最终响应
		// 简单检查：必须以\r\n结尾
		return bytes.HasSuffix(data, []byte("\r\n"))
	default:
		// 其他情况，不认为是最终响应
		return false
	}
}

// splitFunc 自定义数据分割函数
func (s *tcpStream) splitFunc(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if s.parser == nil {
		return 0, nil, nil
	}

	// 根据协议类型使用不同的分割策略
	switch s.parser.GetProtocol() {
	case "redis":
		return s.splitRedis(data, atEOF)
	case "postgres":
		return s.splitPostgres(data, atEOF)
	case "sqlserver":
		return s.splitSQLServer(data, atEOF)
	case "minio":
		return s.splitHTTP(data, atEOF)
	case "rocketmq":
		return s.splitRocketMQ(data, atEOF)
	default:
		// 默认按行分割
		return bufio.ScanLines(data, atEOF)
	}
}
