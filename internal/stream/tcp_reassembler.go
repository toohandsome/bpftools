//go:build linux
// +build linux

package stream

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
)

// min 辅助函数
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// isHTTPRequest 检查字符串是否以HTTP请求方法开头
func isHTTPRequest(data string) bool {
	methods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "}
	for _, method := range methods {
		if strings.HasPrefix(data, method) {
			return true
		}
	}
	return false
}

// isHTTPResponse 检查字符串是否以HTTP响应状态行开头
func isHTTPResponse(data string) bool {
	return strings.HasPrefix(data, "HTTP/1.") || strings.HasPrefix(data, "HTTP/2")
}

// HTTPStreamProcessor 处理TCP流重组和HTTP解析的核心组件
type HTTPStreamProcessor struct {
	assembler   *tcpassembly.Assembler
	streamPool  *tcpassembly.StreamPool
	onEvent     func([]byte) // 事件回调函数
	mu          sync.RWMutex
	activeFlows map[string]*FlowContext
}

// FlowContext 流上下文信息
type FlowContext struct {
	SrcIP    string
	SrcPort  int
	DstIP    string
	DstPort  int
	PID      int
	Comm     string
	FD       int32
	LastSeen time.Time
}

// HTTPStream 实现tcpassembly.Stream接口，处理HTTP流
type HTTPStream struct {
	net, transport      gopacket.Flow
	reversed            bool
	processor           *HTTPStreamProcessor
	flowContext         *FlowContext
	buffer              bytes.Buffer
	isRequest           bool // true: 请求流, false: 响应流
	directionDetermined bool // 方向是否已经确定
}

// HTTPStreamFactory 创建HTTP流的工厂
type HTTPStreamFactory struct {
	processor *HTTPStreamProcessor
}

// New 创建新的HTTP流重组处理器
func NewHTTPStreamProcessor(onEvent func([]byte)) *HTTPStreamProcessor {
	processor := &HTTPStreamProcessor{
		onEvent:     onEvent,
		activeFlows: make(map[string]*FlowContext),
	}

	// 创建流工厂和连接池
	streamFactory := &HTTPStreamFactory{processor: processor}
	processor.streamPool = tcpassembly.NewStreamPool(streamFactory)
	processor.assembler = tcpassembly.NewAssembler(processor.streamPool)

	// 设置连接超时
	processor.assembler.MaxBufferedPagesPerConnection = 16
	processor.assembler.MaxBufferedPagesTotal = 4096

	return processor
}

// New 实现StreamFactory接口
func (factory *HTTPStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	stream := &HTTPStream{
		net:       net,
		transport: transport,
		processor: factory.processor,
		// 初始不判断方向，等收到数据后动态判断
		isRequest: false, // 默认值，会在第一次收到数据时动态判断
	}

	// 从活跃流中获取上下文信息
	flowKey := fmt.Sprintf("%s:%s->%s:%s", net.Src(), transport.Src(), net.Dst(), transport.Dst())
	factory.processor.mu.RLock()
	if ctx, exists := factory.processor.activeFlows[flowKey]; exists {
		stream.flowContext = ctx
	}
	factory.processor.mu.RUnlock()

	log.Printf("Created new HTTP stream: %s, isRequest: %v (will be determined dynamically)", flowKey, stream.isRequest)
	return stream
}

// Reassembled 处理重组的TCP数据
func (stream *HTTPStream) Reassembled(reassembly []tcpassembly.Reassembly) {
	log.Printf("Reassembled called for stream: %s, reassembly count: %d",
		stream.transport.String(), len(reassembly))

	for i, r := range reassembly {
		if r.Bytes == nil {
			log.Printf("Reassembly %d: nil bytes, skipping", i)
			continue
		}

		log.Printf("Reassembly %d: %d bytes, start=%d, end=%d",
			i, len(r.Bytes), r.Start, r.End)
		log.Printf("Reassembly %d data preview: %q", i, string(r.Bytes[:min(50, len(r.Bytes))]))

		// 每次重新判断方向，因为同一个flow可能同时包含请求和响应
		// 先检查这次数据的方向
		dataStr := string(r.Bytes)
		if isHTTPRequest(dataStr) {
			// 这是请求数据
			log.Printf("Processing as HTTP request")
			stream.processHTTPData(r.Bytes, true)
		} else if isHTTPResponse(dataStr) {
			// 这是响应数据
			log.Printf("Processing as HTTP response")
			stream.processHTTPData(r.Bytes, false)
		} else {
			// 未知数据类型，根据缓冲区内容判断
			log.Printf("Unknown data type, buffering for later processing")
			stream.buffer.Write(r.Bytes)
			stream.tryParseHTTP()
		}
	}
}

// tryParseHTTP 尝试解析HTTP消息
func (stream *HTTPStream) tryParseHTTP() {
	log.Printf("tryParseHTTP called, buffer size: %d, isRequest: %v, directionDetermined: %v",
		stream.buffer.Len(), stream.isRequest, stream.directionDetermined)

	if stream.buffer.Len() == 0 {
		log.Printf("Buffer is empty, returning")
		return
	}

	// 如果方向未确定，先根据数据内容判断方向
	if !stream.directionDetermined {
		bufferStr := stream.buffer.String()
		log.Printf("Determining direction from buffer content: %q", bufferStr[:min(100, len(bufferStr))])

		// 检查是否以HTTP方法开头（请求）
		if isHTTPRequest(bufferStr) {
			stream.isRequest = true
			stream.directionDetermined = true
			log.Printf("Detected HTTP request")
		} else if isHTTPResponse(bufferStr) {
			// 检查是否以HTTP/1.x开头（响应）
			stream.isRequest = false
			stream.directionDetermined = true
			log.Printf("Detected HTTP response")
		} else {
			// 数据不足或不是HTTP，等待更多数据
			log.Printf("Cannot determine direction yet, waiting for more data")
			return
		}
	}

	log.Printf("Buffer content preview: %q",
		string(stream.buffer.Bytes()[:min(100, stream.buffer.Len())]))

	for {
		// 创建缓冲区读取器
		reader := bufio.NewReader(bytes.NewReader(stream.buffer.Bytes()))

		var httpData map[string]interface{}

		if stream.isRequest {
			// 解析HTTP请求
			req, err := http.ReadRequest(reader)
			if err != nil {
				if err == io.EOF || err == io.ErrUnexpectedEOF {
					// 数据不完整，等待更多数据
					log.Printf("Incomplete HTTP request data, waiting for more: %v", err)
					break
				}
				// 解析错误，清空缓冲区
				log.Printf("Failed to parse HTTP request: %v", err)
				stream.buffer.Reset()
				break
			}
			httpData = stream.convertRequest(req)
			log.Printf("Successfully parsed HTTP request: %s %s", req.Method, req.URL.String())
		} else {
			// 解析HTTP响应
			resp, err := http.ReadResponse(reader, nil)
			if err != nil {
				if err == io.EOF || err == io.ErrUnexpectedEOF {
					// 数据不完整，等待更多数据
					log.Printf("Incomplete HTTP response data, waiting for more: %v", err)
					break
				}
				// 解析错误，清空缓冲区
				log.Printf("Failed to parse HTTP response: %v", err)
				stream.buffer.Reset()
				break
			}
			httpData = stream.convertResponse(resp)
			log.Printf("Successfully parsed HTTP response: %s", resp.Status)
		}

		// 发送解析后的HTTP事件
		stream.emitHTTPEvent(httpData)

		// 计算已处理的字节数并从缓冲区移除
		remaining := stream.buffer.Len() - int(reader.Size())
		if remaining > 0 {
			newBuffer := make([]byte, remaining)
			copy(newBuffer, stream.buffer.Bytes()[stream.buffer.Len()-remaining:])
			stream.buffer.Reset()
			stream.buffer.Write(newBuffer)
		} else {
			stream.buffer.Reset()
			break
		}
	}
}

// processHTTPData 处理明确方向的HTTP数据
func (stream *HTTPStream) processHTTPData(data []byte, isRequest bool) {
	// 创建临时缓冲区处理这次数据
	tempBuffer := bytes.NewBuffer(data)
	reader := bufio.NewReader(tempBuffer)

	var httpData map[string]interface{}

	if isRequest {
		// 解析HTTP请求
		req, err := http.ReadRequest(reader)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				// 数据不完整，缓存等待更多数据
				log.Printf("Incomplete HTTP request data, buffering: %v", err)
				stream.buffer.Write(data)
				stream.isRequest = true
				stream.directionDetermined = true
				stream.tryParseHTTP()
				return
			}
			log.Printf("Failed to parse HTTP request: %v", err)
			return
		}
		httpData = stream.convertRequest(req)
		log.Printf("Successfully parsed HTTP request: %s %s", req.Method, req.URL.String())
	} else {
		// 解析HTTP响应
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				// 数据不完整，缓存等待更多数据
				log.Printf("Incomplete HTTP response data, buffering: %v", err)
				stream.buffer.Write(data)
				stream.isRequest = false
				stream.directionDetermined = true
				stream.tryParseHTTP()
				return
			}
			log.Printf("Failed to parse HTTP response: %v", err)
			return
		}
		httpData = stream.convertResponse(resp)
		log.Printf("Successfully parsed HTTP response: %s", resp.Status)
	}

	// 临时设置流方向用于事件发送
	originalIsRequest := stream.isRequest
	stream.isRequest = isRequest

	// 发送解析后的HTTP事件
	stream.emitHTTPEvent(httpData)

	// 恢复原有的流状态
	stream.isRequest = originalIsRequest
}

// convertRequest 将http.Request转换为事件数据
func (stream *HTTPStream) convertRequest(req *http.Request) map[string]interface{} {
	headers := make(map[string]string)
	for k, v := range req.Header {
		headers[k] = strings.Join(v, ", ")
	}
	headers[":method"] = req.Method
	headers[":path"] = req.URL.Path
	headers[":scheme"] = req.URL.Scheme
	if req.URL.RawQuery != "" {
		headers[":query"] = req.URL.RawQuery
	}

	// 读取请求体
	var body string
	if req.Body != nil {
		bodyBytes, err := io.ReadAll(req.Body)
		if err == nil {
			body = string(bodyBytes)
		}
		req.Body.Close()
	}

	return map[string]interface{}{
		"direction": "request",
		"method":    req.Method,
		"url":       req.URL.String(),
		"headers":   headers,
		"body":      body,
	}
}

// convertResponse 将http.Response转换为事件数据
func (stream *HTTPStream) convertResponse(resp *http.Response) map[string]interface{} {
	headers := make(map[string]string)
	for k, v := range resp.Header {
		headers[k] = strings.Join(v, ", ")
	}
	headers[":status"] = fmt.Sprintf("%d", resp.StatusCode)
	headers[":status-text"] = resp.Status

	// 读取响应体
	var body string
	if resp.Body != nil {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err == nil {
			body = string(bodyBytes)
		}
		resp.Body.Close()
	}

	return map[string]interface{}{
		"direction": "response",
		"status":    resp.Status,
		"headers":   headers,
		"body":      body,
	}
}

// emitHTTPEvent 发送HTTP事件
func (stream *HTTPStream) emitHTTPEvent(httpData map[string]interface{}) {
	// 构造完整的事件数据
	event := map[string]interface{}{
		"time": time.Now().UnixMilli(),
		"wire": func() string {
			if stream.isRequest {
				return "send"
			}
			return "recv"
		}(),
		"http": httpData,
	}

	// 添加流上下文信息
	if stream.flowContext != nil {
		event["pid"] = stream.flowContext.PID
		event["comm"] = stream.flowContext.Comm
		event["fd"] = stream.flowContext.FD
		if stream.isRequest {
			event["srcIP"] = stream.flowContext.SrcIP
			event["srcPort"] = stream.flowContext.SrcPort
			event["dstIP"] = stream.flowContext.DstIP
			event["dstPort"] = stream.flowContext.DstPort
		} else {
			// 响应方向相反
			event["srcIP"] = stream.flowContext.DstIP
			event["srcPort"] = stream.flowContext.DstPort
			event["dstIP"] = stream.flowContext.SrcIP
			event["dstPort"] = stream.flowContext.SrcPort
		}
	} else {
		// 从网络流信息中提取IP和端口
		srcIP, srcPort := parseEndpoint(stream.net.Src().String(), stream.transport.Src().String())
		dstIP, dstPort := parseEndpoint(stream.net.Dst().String(), stream.transport.Dst().String())
		event["srcIP"] = srcIP
		event["srcPort"] = srcPort
		event["dstIP"] = dstIP
		event["dstPort"] = dstPort
	}

	// 发送事件
	if stream.processor.onEvent != nil {
		if data, err := json.Marshal(event); err == nil {
			log.Printf("Emitting HTTP event to SSE: %s", string(data))
			stream.processor.onEvent(data)
			log.Printf("Successfully sent HTTP event to SSE")
		} else {
			log.Printf("Failed to marshal HTTP event: %v", err)
		}
	} else {
		log.Printf("No onEvent callback registered")
	}

	log.Printf("HTTP %s: %s", httpData["direction"],
		func() string {
			if method, ok := httpData["method"]; ok {
				return fmt.Sprintf("%s %s", method, httpData["url"])
			}
			return httpData["status"].(string)
		}())
}

// ReassemblyComplete 流重组完成
func (stream *HTTPStream) ReassemblyComplete() {
	// 处理剩余数据
	if stream.buffer.Len() > 0 {
		stream.tryParseHTTP()
	}
}

// UpdateFlowContext 更新流上下文信息
func (processor *HTTPStreamProcessor) UpdateFlowContext(srcIP string, srcPort int, dstIP string, dstPort int, pid int, comm string, fd int32) {
	flowKey := fmt.Sprintf("%s:%d->%s:%d", srcIP, srcPort, dstIP, dstPort)

	processor.mu.Lock()
	processor.activeFlows[flowKey] = &FlowContext{
		SrcIP:    srcIP,
		SrcPort:  srcPort,
		DstIP:    dstIP,
		DstPort:  dstPort,
		PID:      pid,
		Comm:     comm,
		FD:       fd,
		LastSeen: time.Now(),
	}
	processor.mu.Unlock()
}

// ProcessPacket 处理数据包
func (processor *HTTPStreamProcessor) ProcessPacket(packet gopacket.Packet) {
	log.Printf("ProcessPacket called, packet: %v", packet)

	// 交给assembler处理
	netLayer := packet.NetworkLayer()
	//log.Printf("Network layer: %v", netLayer)

	if netLayer != nil {
		tcpLayer := packet.TransportLayer()
		//log.Printf("Transport layer: %v", tcpLayer)

		if tcpLayer != nil {
			// 需要从层中获取Flow信息
			netFlow := netLayer.NetworkFlow()
			tcpFlow := tcpLayer.TransportFlow()

			log.Printf("Network flow: %s, TCP flow: %s", netFlow, tcpFlow)

			// 检查是否是TCP层
			if tcp, ok := tcpLayer.(*layers.TCP); ok {
				log.Printf("TCP layer details: Seq=%d, Ack=%d, PSH=%v, ACK=%v, SYN=%v, FIN=%v",
					tcp.Seq, tcp.Ack, tcp.PSH, tcp.ACK, tcp.SYN, tcp.FIN)

				// 只处理有载荷的数据包
				if appLayer := packet.ApplicationLayer(); appLayer != nil {
					log.Printf("Application layer payload: %d bytes", len(appLayer.Payload()))
					log.Printf("Payload preview: %q", string(appLayer.Payload()[:min(50, len(appLayer.Payload()))]))
				}

				processor.assembler.AssembleWithTimestamp(
					netFlow,
					tcp,
					packet.Metadata().Timestamp,
				)
				log.Printf("Successfully called assembler.AssembleWithTimestamp")
			} else {
				log.Printf("Transport layer is not TCP: %T", tcpLayer)
			}
		} else {
			log.Printf("No transport layer found")
		}
	} else {
		log.Printf("No network layer found")
	}
}

// FlushOlderThan 清理旧连接
func (processor *HTTPStreamProcessor) FlushOlderThan(t time.Time) {
	processor.assembler.FlushOlderThan(t)

	// 清理过期的流上下文
	processor.mu.Lock()
	for key, ctx := range processor.activeFlows {
		if ctx.LastSeen.Before(t) {
			delete(processor.activeFlows, key)
		}
	}
	processor.mu.Unlock()
}

// parseEndpoint 解析端点信息
func parseEndpoint(ip, port string) (string, int) {
	// 这里简化处理，实际可能需要更复杂的解析
	return ip, 0 // gopacket会提供正确的格式
}
