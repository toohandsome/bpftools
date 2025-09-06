// Package capture 提供网络包捕获功能
package capture

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"

	"github.com/myserver/go-server/ebpf/middle/config"
	"github.com/myserver/go-server/ebpf/middle/types"
)

// Capture 网络包捕获器
type Capture struct {
	config    *config.Config
	handle    *pcap.Handle
	assembler *tcpassembly.Assembler
	factory   *streamFactory
	mu        sync.RWMutex
	stats     *types.Stats
	callback  func(*types.RequestResponse)

	// 全局请求存储（跨流共享）
	pendingRequests map[string]*types.Message
	requestsMu      sync.RWMutex

	// 待匹配响应缓存（新增）
	pendingResponses map[string]*types.Message
	responsesMu      sync.RWMutex

	// 上下文控制
	ctx    context.Context
	cancel context.CancelFunc
}

// NewCapture 创建新的包捕获器
func NewCapture(cfg *config.Config) (*Capture, error) {
	// 打开网络接口（使用较短的超时时间而不是BlockForever）
	handle, err := pcap.OpenLive(cfg.Interface, int32(cfg.BufferSize), true, time.Second)
	if err != nil {
		return nil, fmt.Errorf("打开网络接口失败: %v", err)
	}

	// 设置BPF过滤器
	if err := handle.SetBPFFilter(cfg.BuildBPFFilter()); err != nil {
		handle.Close()
		return nil, fmt.Errorf("设置BPF过滤器失败: %v", err)
	}

	c := &Capture{
		config: cfg,
		handle: handle,
		stats: &types.Stats{
			StartTime: time.Now(),
		},
		pendingRequests:  make(map[string]*types.Message),
		pendingResponses: make(map[string]*types.Message),
	}

	// 创建上下文
	c.ctx, c.cancel = context.WithCancel(context.Background())

	// 创建流工厂
	c.factory = &streamFactory{
		capture: c,
	}

	// 创建TCP组装器
	c.assembler = tcpassembly.NewAssembler(tcpassembly.NewStreamPool(c.factory))

	return c, nil
}

// Start 启动包捕获
func (c *Capture) Start(ctx context.Context) error {
	if c.config.Verbose {
		log.Printf("开始在接口 %s 上捕获包，过滤器: %s", c.config.Interface, c.config.BuildBPFFilter())
	}

	packetSource := gopacket.NewPacketSource(c.handle, c.handle.LinkType())
	packets := packetSource.Packets()

	// 启动定时清理（改为更频繁的清理）
	// 每1秒检查一次，实现近实时的请求响应匹配
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	// 用于统计捕获到的包数量
	packetCount := 0
	lastLogTime := time.Now()

	// 设置包捕获超时时间，避免无限阻塞
	packetTimeout := time.NewTicker(100 * time.Millisecond)
	defer packetTimeout.Stop()

	for {
		select {
		case <-ctx.Done():
			if c.config.Verbose {
				log.Printf("收到停止信号，已捕获 %d 个包", packetCount)
			}
			return ctx.Err()
		case <-ticker.C:
			// 定期清理旧连接（使用更短的超时时间）
			// 原来30秒太长，改为2秒强制刷新不完整的流
			c.assembler.FlushOlderThan(time.Now().Add(-2 * time.Second))

			// 清理过期的待匹配请求
			c.cleanupExpiredRequests()

			// 定期输出统计信息
			// if c.config.Verbose {
			// 	log.Printf("已捕获 %d 个包，待匹配请求数: %d", packetCount, len(c.pendingRequests))
			// }
		case <-packetTimeout.C:
			// 定期检查上下文是否已取消，避免长时间阻塞在packets通道
			select {
			case <-ctx.Done():
				if c.config.Verbose {
					log.Printf("在超时检查中收到停止信号，已捕获 %d 个包", packetCount)
				}
				return ctx.Err()
			default:
				// 继续循环
			}
		case packet := <-packets:
			if packet == nil {
				continue
			}
			packetCount++

			// 每1000个包输出一次统计
			if c.config.Verbose && packetCount%1000 == 0 {
				log.Printf("已处理 %d 个包", packetCount)
			} else if c.config.Verbose && time.Since(lastLogTime) > 10*time.Second {
				log.Printf("当前已处理 %d 个包", packetCount)
				lastLogTime = time.Now()
			}

			c.processPacket(packet)
		}
	}
}

// Stop 停止包捕获
func (c *Capture) Stop() {
	if c.config.Verbose {
		log.Printf("正在停止包捕获...")
	}

	// 取消上下文，通知所有goroutine停止
	if c.cancel != nil {
		c.cancel()
		if c.config.Verbose {
			log.Printf("已取消上下文")
		}
	}

	if c.handle != nil {
		c.handle.Close()
		if c.config.Verbose {
			log.Printf("已关闭网络句柄")
		}
	}

	if c.assembler != nil {
		c.assembler.FlushAll()
		if c.config.Verbose {
			log.Printf("已刷新TCP组装器")
		}
	}

	if c.config.Verbose {
		log.Printf("包捕获已停止")
	}
}

// SetCallback 设置请求响应回调
func (c *Capture) SetCallback(callback func(*types.RequestResponse)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.callback = callback
}

// 处理单个数据包
func (c *Capture) processPacket(packet gopacket.Packet) {
	// 提取网络层
	netLayer := packet.NetworkLayer()
	if netLayer == nil {
		return
	}

	// 提取传输层
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}

	tcp, _ := tcpLayer.(*layers.TCP)
	ip, _ := netLayer.(*layers.IPv4)

	if ip == nil || tcp == nil {
		return
	}

	// 检查是否为目标端口（支持多端口）
	allPorts := c.config.GetAllPorts()
	isTargetPort := false
	currentSrcPort := int(tcp.SrcPort)
	currentDstPort := int(tcp.DstPort)

	// 检查是否匹配任何目标端口
	for _, port := range allPorts {
		if currentSrcPort == port || currentDstPort == port {
			isTargetPort = true
			break
		}
	}

	// 兼容性检查：如果没有多端口配置，使用单端口模式
	if !isTargetPort && c.config.Port != 0 {
		isTargetPort = (currentSrcPort == c.config.Port || currentDstPort == c.config.Port)
	}

	if !isTargetPort {
		return
	}

	// 如果是verbose模式，输出包信息
	if c.config.Verbose {

		// 打印载荷明文（最长32字节）
		if len(tcp.Payload) > 0 {
			maxLen := len(tcp.Payload)
			if maxLen > 64 {
				maxLen = 64
			}

			// 输出可打印字符（最长32字节）
			// printableStr := ""
			// for i := 0; i < maxLen; i++ {
			// 	if tcp.Payload[i] >= 32 && tcp.Payload[i] <= 126 {
			// 		printableStr += string(tcp.Payload[i])
			// 	} else if tcp.Payload[i] == 13 {
			// 		printableStr += "\\r"
			// 	} else if tcp.Payload[i] == 10 {
			// 		printableStr += "\\n"
			// 	} else {
			// 		printableStr += "."
			// 	}
			// }

			// 根据是否截断显示不同的信息
			// if len(tcp.Payload) > 32 {
			// 	// log.Printf("  载荷内容 [总长度%d字节，显示前32字节]: %s", len(tcp.Payload), hexStr)
			// 	log.Printf("  明文内容: %q -> %s", string(tcp.Payload[:maxLen]), printableStr)
			// } else {
			// 	// log.Printf("  载荷内容 [%d字节]: %s", len(tcp.Payload), hexStr)
			// 	log.Printf("  明文内容: %q -> %s", string(tcp.Payload[:maxLen]), printableStr)
			// }

		}
	}

	// 提供给TCP重组器进行流重组
	if len(tcp.Payload) > 0 {
		c.assembler.AssembleWithTimestamp(
			packet.NetworkLayer().NetworkFlow(),
			tcp,
			packet.Metadata().Timestamp,
		)
	}

	// 立即刷新组装器，确保数据能实时处理
	// c.assembler.FlushAll()

}

// onRequestResponse 请求响应事件处理
func (c *Capture) onRequestResponse(rr *types.RequestResponse) {
	c.mu.Lock()
	callback := c.callback
	c.mu.Unlock()

	if callback != nil {
		callback(rr)
	}

}

// storeRequest 存储请求到全局缓存
func (c *Capture) storeRequest(msg *types.Message) {
	if msg == nil || msg.ID == "" {
		return
	}

	c.requestsMu.Lock()
	c.pendingRequests[msg.ID] = msg
	// currentCount := len(c.pendingRequests)
	c.requestsMu.Unlock()

	// if c.config.Verbose {
	// 	log.Printf("📋 存储请求: %s, 连接: %s -> %s, 当前待匹配请求数: %d",
	// 		msg.ID, msg.Connection.LocalAddr, msg.Connection.RemoteAddr, len(c.pendingRequests))
	// }

	// 检查是否有等待的响应需要匹配
	c.checkPendingResponses(msg)
}

// matchAndRemoveRequest 匹配并移除请求
func (c *Capture) matchAndRemoveRequest(connInfo *types.Connection) *types.Message {
	c.requestsMu.Lock()
	defer c.requestsMu.Unlock()

	// 简化匹配策略：找到同一连接上最早的请求
	var oldestRequest *types.Message
	var oldestID string

	for id, req := range c.pendingRequests {
		// 检查连接匹配
		if c.isConnectionMatch(req.Connection, connInfo) {
			// 找到最早的请求
			if oldestRequest == nil || req.Timestamp.Before(oldestRequest.Timestamp) {
				oldestRequest = req
				oldestID = id
			}
		}
	}

	if oldestID != "" {
		delete(c.pendingRequests, oldestID)
		// if c.config.Verbose {
		// 	log.Printf("✅ 匹配到请求: %s, 剩余待匹配请求数: %d", oldestID, len(c.pendingRequests))
		// }
		return oldestRequest
	}

	// if c.config.Verbose {
	// 	// log.Printf("⚠️ 未找到匹配的请求，当前待匹配请求数: %d", len(c.pendingRequests))
	// 	// 打印当前所有待匹配请求的连接信息
	// 	log.Printf("📝 待匹配请求列表:")
	// 	for id, req := range c.pendingRequests {
	// 		log.Printf("• 请求ID: %s, 连接: %s -> %s (方向: %v), 时间: %v",
	// 			id, req.Connection.LocalAddr, req.Connection.RemoteAddr, req.Connection.Direction, req.Timestamp.Format("15:04:05.000"))
	// 	}
	// 	log.Printf("🗑️ 当前响应连接: %s -> %s (方向: %v)", connInfo.LocalAddr, connInfo.RemoteAddr, connInfo.Direction)
	// }

	return nil
}

// isConnectionMatch 检查连接是否匹配
func (c *Capture) isConnectionMatch(reqConn, respConn *types.Connection) bool {
	if reqConn == nil || respConn == nil {
		return false
	}

	// if c.config.Verbose {
	// 	log.Printf("🔍 连接匹配检查: 请求(%s->%s) vs 响应(%s->%s)",
	// 		reqConn.LocalAddr, reqConn.RemoteAddr, respConn.LocalAddr, respConn.RemoteAddr)

	// 	// 检查匹配结果
	// 	match := (reqConn.LocalAddr == respConn.RemoteAddr && reqConn.RemoteAddr == respConn.LocalAddr)
	// 	log.Printf("🔍 匹配结果: %v", match)
	// 	return match
	// }

	// 上反连接匹配：请求的本地地址 == 响应的远程地址，请求的远程地址 == 响应的本地地址
	return (reqConn.LocalAddr == respConn.RemoteAddr && reqConn.RemoteAddr == respConn.LocalAddr)
}

// cleanupExpiredRequests 清理过期的待匹配请求
func (c *Capture) cleanupExpiredRequests() {
	c.requestsMu.Lock()
	defer c.requestsMu.Unlock()

	now := time.Now()
	expiredCount := 0
	for id, req := range c.pendingRequests {
		// 清理超过 2 倍超时时间的请求
		if now.Sub(req.Timestamp) > c.config.Timeout*2 {
			delete(c.pendingRequests, id)
			expiredCount++
		}
	}

	if expiredCount > 0 && c.config.Verbose {
		log.Printf("🗑️ 清理了 %d 个过期请求，剩余待匹配请求数: %d", expiredCount, len(c.pendingRequests))
	}

	// 同时清理过期的响应
	c.responsesMu.Lock()
	respExpiredCount := 0
	for id, resp := range c.pendingResponses {
		if now.Sub(resp.Timestamp) > c.config.Timeout {
			delete(c.pendingResponses, id)
			respExpiredCount++
		}
	}
	c.responsesMu.Unlock()

	if respExpiredCount > 0 && c.config.Verbose {
		log.Printf("🗑️ 清理了 %d 个过期响应，剩余待匹配响应数: %d", respExpiredCount, len(c.pendingResponses))
	}
}

// checkPendingResponses 检查是否有等待的响应需要匹配
func (c *Capture) checkPendingResponses(request *types.Message) {
	c.responsesMu.Lock()
	defer c.responsesMu.Unlock()

	// 查找匹配的响应
	for id, response := range c.pendingResponses {
		if c.isConnectionMatch(request.Connection, response.Connection) {
			// 找到匹配的响应
			delete(c.pendingResponses, id)

			// 创建请求响应对
			rr := &types.RequestResponse{
				Request:    request,
				Response:   response,
				Connection: request.Connection,
				Duration:   response.Timestamp.Sub(request.Timestamp),
				Success:    !isErrorResponse(response),
			}

			// if c.config.Verbose {
			// 	log.Printf("✅ 延迟匹配成功: 请求=%s, 响应=%s, 耗时=%v",
			// 		request.ID, response.ID, rr.Duration)
			// }

			// 通知监控器
			c.onRequestResponse(rr)
			return
		}
	}
}

// storeOrMatchResponse 存储响应或匹配请求
func (c *Capture) storeOrMatchResponse(response *types.Message) bool {
	// 先尝试匹配请求
	request := c.matchAndRemoveRequest(response.Connection)
	if request != nil {
		// 找到匹配的请求，创建请求响应对
		rr := &types.RequestResponse{
			Request:    request,
			Response:   response,
			Connection: request.Connection,
			Duration:   response.Timestamp.Sub(request.Timestamp),
			Success:    !isErrorResponse(response),
		}

		// if c.config.Verbose {
		// 	log.Printf("✅ 即时匹配成功: 请求=%s, 响应=%s, 耗时=%v",
		// 		request.ID, response.ID, rr.Duration)
		// }

		// 通知监控器
		c.onRequestResponse(rr)
		return true // 返回true表示已匹配
	}

	// 没有找到匹配的请求，缓存响应
	c.responsesMu.Lock()
	c.pendingResponses[response.ID] = response
	c.responsesMu.Unlock()

	// if c.config.Verbose {
	// 	log.Printf("📋 缓存响应等待匹配: %s, 连接: %s -> %s, 当前待匹配响应数: %d",
	// 		response.ID, response.Connection.LocalAddr, response.Connection.RemoteAddr, len(c.pendingResponses))
	// }

	return false // 返回false表示未匹配，已缓存
}

// isErrorResponse 判断是否为错误响应
func isErrorResponse(msg *types.Message) bool {
	// 根据不同协议判断是否为错误响应
	if msg.ParsedData == nil {
		return false
	}

	switch msg.Command {
	case "Error":
		return true
	case "ErrorResponse":
		return true
	default:
		// Redis协议：错误响应以-开头
		if len(msg.Data) > 0 && msg.Data[0] == '-' {
			return true
		}
		return false
	}
}
