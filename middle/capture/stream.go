// Package capture - TCP流处理器
package capture

import (
	"bytes"
	"context"
	"fmt"
	"io"
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
	// 为同一连接共享解析器实例
	parsers map[string]types.ProtocolParser // 键为连接字符串，值为解析器实例
	mu      sync.RWMutex                    // 保护parsers map
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

	// 使用标准化的连接键，确保双向数据包使用相同的connKey
	var connKey string
	if conn.LocalAddr < conn.RemoteAddr {
		connKey = fmt.Sprintf("%s<->%s", conn.LocalAddr, conn.RemoteAddr)
	} else {
		connKey = fmt.Sprintf("%s<->%s", conn.RemoteAddr, conn.LocalAddr)
	}

	// 重要：为每个连接创建独立的解析器实例，避免解析器状态混乱
	parser := factory.getOrCreateParser(middlewareType, connKey)

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
	// 	// log.Printf("🌊 创建新TCP流: %s->%s, 方向=%v, 中间件=%s",
	// 		conn.LocalAddr, conn.RemoteAddr, conn.Direction, middlewareType)
	// }

	return &stream.reader
}

// getOrCreateParser 获取或创建独立的解析器实例（每个连接一个）
func (factory *streamFactory) getOrCreateParser(middlewareType string, connKey string) types.ProtocolParser {
	factory.mu.Lock()
	defer factory.mu.Unlock()

	// 初始化parsers map
	if factory.parsers == nil {
		factory.parsers = make(map[string]types.ProtocolParser)
	}

	// 使用连接键+中间件类型作为解析器键，确保每个连接有独立的解析器
	parserKey := fmt.Sprintf("%s_%s", middlewareType, connKey)

	// 检查是否已存在解析器
	if parser, exists := factory.parsers[parserKey]; exists {
		if factory.capture.config.Verbose {
			// log.Printf("🔄 复用现有解析器: %s, 连接=%s", middlewareType, connKey)
		}
		return parser
	}

	// 创建新的解析器实例
	parser := parsers.GetParserWithConfig(middlewareType, factory.capture.config.Verbose)
	factory.parsers[parserKey] = parser

	if factory.capture.config.Verbose {
		// log.Printf("🆕 创建新解析器: %s, 连接=%s", middlewareType, connKey)
	}

	return parser
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
		return
	}

	// 使用简单的字节读取，避免Scanner造成的时序问题
	buf := make([]byte, 4096)
	readTimeout := time.NewTicker(10 * time.Millisecond)
	defer readTimeout.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-readTimeout.C:
			// 读取数据（非阻塞）
			n, err := s.reader.Read(buf)
			if err != nil {
				if err == io.EOF {
					return
				}
				// 其他错误
				if s.factory.capture.config.Verbose {
					// log.Printf("TCP流读取错误: %v", err)
				}
				return
			}

			if n > 0 {
				// 复制读取到的数据
				data := make([]byte, n)
				copy(data, buf[:n])

				// 累积到缓冲区
				s.mu.Lock()
				s.buffer = append(s.buffer, data...)
				s.lastActive = time.Now()

				// 处理缓冲区中的完整消息
				s.processBuffer()
				s.mu.Unlock()
			}
		}
	}
}

// processBuffer 从缓冲区中提取并处理完整的Redis消息
func (s *tcpStream) processBuffer() {
	for len(s.buffer) > 0 {
		// 尝试提取完整的Redis消息
		msgLen := s.extractCompleteMessage()
		if msgLen <= 0 {
			// 没有完整消息，等待更多数据
			break
		}

		// 提取消息数据
		msgData := make([]byte, msgLen)
		copy(msgData, s.buffer[:msgLen])

		// 从缓冲区中移除已处理的数据
		s.buffer = s.buffer[msgLen:]

		// 处理消息
		s.processData(msgData)
	}

	// 清理过大的缓冲区（防止内存泄漏）
	if len(s.buffer) > 1024*1024 { // 1MB
		if s.factory.capture.config.Verbose {
			// log.Printf("⚠️ 缓冲区过大，清空: %d bytes", len(s.buffer))
		}
		s.buffer = nil
	}
}

// extractCompleteMessage 提取完整的Redis消息（返回消息长度）
func (s *tcpStream) extractCompleteMessage() int {
	if len(s.buffer) == 0 {
		return 0
	}

	// 根据Redis RESP协议的首字节判断消息类型
	switch s.buffer[0] {
	case '+':
		// 简单字符串 (+OK\r\n)
		return s.findLineEnd()
	case '-':
		// 错误响应 (-ERR ...\r\n)
		return s.findLineEnd()
	case ':':
		// 整数响应 (:123\r\n)
		return s.findLineEnd()
	case '$':
		// 批量字符串 ($5\r\nhello\r\n)
		return s.extractBulkString()
	case '*':
		// 数组 (*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n)
		return s.extractArray()
	default:
		// 内联命令或非标准格式，按行处理
		return s.findLineEnd()
	}
}

// findLineEnd 查找\r\n结尾的行
func (s *tcpStream) findLineEnd() int {
	for i := 0; i < len(s.buffer)-1; i++ {
		if s.buffer[i] == '\r' && s.buffer[i+1] == '\n' {
			return i + 2 // 包含\r\n
		}
	}
	return 0 // 没有找到完整的行
}

// extractBulkString 提取批量字符串
func (s *tcpStream) extractBulkString() int {
	// 找到长度行的结尾
	lengthEnd := s.findLineEnd()
	if lengthEnd == 0 {
		return 0 // 长度行不完整
	}

	// 解析长度
	lengthStr := string(s.buffer[1 : lengthEnd-2])
	length := 0
	for _, r := range lengthStr {
		if r >= '0' && r <= '9' {
			length = length*10 + int(r-'0')
		} else if r == '-' && length == 0 {
			length = -1 // 空值
			break
		}
	}

	if length == -1 {
		// 空值，只返回长度行
		return lengthEnd
	}

	// 检查数据是否完整
	totalLen := lengthEnd + length + 2 // 长度行 + 数据 + \r\n
	if totalLen <= len(s.buffer) {
		return totalLen
	}

	return 0 // 数据不完整
}

// extractArray 提取RESP数组
func (s *tcpStream) extractArray() int {
	// 找到数组长度行的结尾
	lengthEnd := s.findLineEnd()
	if lengthEnd == 0 {
		return 0 // 长度行不完整
	}

	// 解析数组长度
	lengthStr := string(s.buffer[1 : lengthEnd-2])
	arrayLength := 0
	for _, r := range lengthStr {
		if r >= '0' && r <= '9' {
			arrayLength = arrayLength*10 + int(r-'0')
		}
	}

	if arrayLength <= 0 {
		// 空数组，只返回长度行
		return lengthEnd
	}

	// 逐个解析数组元素
	pos := lengthEnd
	for i := 0; i < arrayLength; i++ {
		if pos >= len(s.buffer) {
			return 0 // 数据不完整
		}

		// 递归解析元素
		elemLen := s.extractElementAt(pos)
		if elemLen == 0 {
			return 0 // 元素不完整
		}
		pos += elemLen
	}

	return pos
}

// extractElementAt 从指定位置提取RESP元素
func (s *tcpStream) extractElementAt(offset int) int {
	if offset >= len(s.buffer) {
		return 0
	}

	// 保存原始缓冲区
	originalBuffer := s.buffer
	// 临时修改缓冲区指针
	s.buffer = s.buffer[offset:]

	// 递归调用提取方法
	var elemLen int
	switch s.buffer[0] {
	case '+':
		elemLen = s.findLineEnd()
	case '-':
		elemLen = s.findLineEnd()
	case ':':
		elemLen = s.findLineEnd()
	case '$':
		elemLen = s.extractBulkString()
	case '*':
		elemLen = s.extractArray()
	default:
		elemLen = s.findLineEnd()
	}

	// 恢复原始缓冲区
	s.buffer = originalBuffer

	return elemLen
}

// processData 处理完整的Redis消息数据
func (s *tcpStream) processData(data []byte) {
	if len(data) == 0 {
		return
	}

	// 复制数据到新的字节数组
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	// 判断数据类型
	isRequest := s.parser.IsRequest(dataCopy)
	isResponse := s.parser.IsResponse(dataCopy)

	if s.factory.capture.config.Verbose {
		// log.Printf("🔍 协议分析结果: IsRequest=%v, IsResponse=%v, 首字节=%c", isRequest, isResponse, dataCopy[0])
	}

	if isRequest {
		s.handleRequest(dataCopy)
	} else if isResponse {
		s.handleResponse(dataCopy)
	} else {
		// 非法数据，忽略
		if s.factory.capture.config.Verbose {
			// log.Printf("⚠️ 忽略无效数据: %q", string(dataCopy))
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
	// 	// log.Printf("🔍 处理请求数据: 长度=%d, 数据=%q", len(data), string(data[:maxLen]))
	// }

	msg, err := s.parser.ParseRequest(data)
	if err != nil {
		if s.factory.capture.config.Verbose {
			previewLen := len(data)
			if previewLen > 50 {
				previewLen = 50
			}
			// log.Printf("解析请求失败: %v, 数据预览: %s", err, string(data[:previewLen]))
		}
		return
	}

	// 必须在调用任何高级解析器功能之前设置连接信息
	// 使用统一的时间戳确保一致性
	timestamp := time.Now()
	msg.Connection = s.connection
	msg.Timestamp = timestamp

	// 添加详细的连接调试信息
	if s.factory.capture.config.Verbose {
		// // log.Printf("🔍 请求连接信息: %s -> %s, 方向: %v, 命令: %s, ID: %s",
		// 	msg.Connection.LocalAddr, msg.Connection.RemoteAddr, msg.Connection.Direction, msg.Command, msg.ID)

		// 显示解析的数据
		// if parsedData, ok := msg.ParsedData.([]string); ok {
		// // log.Printf("🔍 解析的命令参数: %v", parsedData)
		// }
	}

	// 分别处理高级解析器和传统解析器
	if advancedParser, ok := s.parser.(*parsers.RedisAdvancedParserAdapter); ok {
		// 高级解析器需要手动注册请求（因为ParseRequest时Connection为nil）
		// if s.factory.capture.config.Verbose {
		// 	// log.Printf("📝 高级解析器处理请求: %s, ID: %s", msg.Command, msg.ID)
		// }
		// 现在手动注册请求，因为连接信息已经设置
		if parsedCmd, ok := msg.ParsedData.(*parsers.RedisParsedCommand); ok {
			advancedParser.GetParser().RegisterRequestManually(msg, parsedCmd)
		}
	} else {
		// 传统解析器需要手动存储请求
		s.factory.capture.storeRequest(msg)
		// 检查是否有等待的响应需要匹配
		s.factory.capture.checkPendingResponses(msg)
	}

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

	// 使用统一的时间戳确保一致性
	timestamp := time.Now()
	msg.Connection = s.connection
	msg.Timestamp = timestamp

	// if s.factory.capture.config.Verbose {
	// 	// log.Printf("🔍 检测到响应数据: 命令=%s, 数据=%q, 系统时间=%v", msg.Command, string(data), time.Now().UnixNano())
	// 	// log.Printf("  - 响应连接信息: LocalAddr=%s, RemoteAddr=%s, Direction=%v",
	// 		msg.Connection.LocalAddr, msg.Connection.RemoteAddr, msg.Connection.Direction)
	// }

	// 判断是否为真正的最终响应（简单字符串或错误响应）
	isFinalResponse := s.isFinalResponse(data)
	if !isFinalResponse {
		if s.factory.capture.config.Verbose {
			// log.Printf("⚠️ 跳过中间数据分片: %s", string(data))
		}
		return
	}

	// if s.factory.capture.config.Verbose {
	// 	// log.Printf("✅ 确认为最终响应，尝试匹配请求")
	// }

	// 优先使用高级Redis解析器进行请求响应匹配
	if advancedParser, ok := s.parser.(*parsers.RedisAdvancedParserAdapter); ok {
		if rr := advancedParser.MatchRequestResponse(msg); rr != nil {
			// 成功匹配，直接通知回调
			s.factory.capture.notifyCallback(rr)
			return
		} else {
			// 高级解析器没有找到匹配，记录调试信息
			// if s.factory.capture.config.Verbose {
			// 	// log.Printf("⚠️ 高级解析器未找到匹配的请求，响应: %s", msg.Command)
			// }
		}
	}

	// 如果高级解析器没有匹配成功，使用传统的匹配机制
	s.factory.capture.storeOrMatchResponse(msg)
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
