// Package monitor - Redis监控器，负责协调请求响应匹配和输出
package monitor

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/myserver/go-server/ebpf/middle/parsers"
	"github.com/myserver/go-server/ebpf/middle/types"
)

// RedisMonitor Redis监控器
type RedisMonitor struct {
	parser   *parsers.RedisEnhancedParser
	callback func(*types.RequestResponse)
	stats    *RedisStats
	verbose  bool
	mu       sync.RWMutex
}

// RedisStats Redis统计信息
type RedisStats struct {
	TotalRequests  int64
	TotalResponses int64
	MatchedPairs   int64
	UnmatchedReqs  int64
	UnmatchedResps int64
	ErrorResponses int64
	AvgLatency     time.Duration
	MaxLatency     time.Duration
	MinLatency     time.Duration
	StartTime      time.Time
	mu             sync.RWMutex
}

// NewRedisMonitor 创建Redis监控器
func NewRedisMonitor(verbose bool) *RedisMonitor {
	config := &parsers.RedisParserConfig{
		MaxContentLength: 64,
		EnableDBTracking: true,
		Verbose:          verbose,
	}

	return &RedisMonitor{
		parser:  parsers.NewRedisEnhancedParser(config),
		verbose: verbose,
		stats: &RedisStats{
			StartTime:  time.Now(),
			MinLatency: time.Hour, // 初始设置为一个大值
		},
	}
}

// Start 启动监控
func (rm *RedisMonitor) Start() error {
	if rm.verbose {
		log.Printf("🚀 Redis监控器启动")
	}
	return nil
}

// Stop 停止监控
func (rm *RedisMonitor) Stop() error {
	if rm.verbose {
		log.Printf("⏹️ Redis监控器停止")
		rm.PrintStats()
	}
	return nil
}

// SetCallback 设置回调函数
func (rm *RedisMonitor) SetCallback(callback func(*types.RequestResponse)) {
	rm.mu.Lock()
	rm.callback = callback
	rm.mu.Unlock()
}

// ProcessRequest 处理请求
func (rm *RedisMonitor) ProcessRequest(data []byte, conn *types.Connection) error {
	// 解析请求
	request, err := rm.parser.ParseRequest(data)
	if err != nil {
		return fmt.Errorf("解析请求失败: %v", err)
	}

	request.Connection = conn

	// 更新统计
	rm.updateRequestStats()

	if rm.verbose {
		log.Printf("📨 Redis请求: %s [%s]", request.Command, rm.parser.GetConnectionKey(conn))
	}

	return nil
}

// ProcessResponse 处理响应
func (rm *RedisMonitor) ProcessResponse(data []byte, conn *types.Connection) error {
	// 解析响应
	response, err := rm.parser.ParseResponse(data)
	if err != nil {
		return fmt.Errorf("解析响应失败: %v", err)
	}

	response.Connection = conn

	// 更新统计
	rm.updateResponseStats(response)

	// 尝试匹配请求
	rr := rm.parser.MatchRequestResponse(response)
	if rr != nil {
		// 匹配成功
		rm.updateMatchStats(rr)

		// 输出匹配结果
		output := rm.parser.FormatRequestResponse(rr)
		fmt.Printf("%s %s\n", time.Now().Format("15:04:05.000"), output)

		// 调用回调
		rm.mu.RLock()
		callback := rm.callback
		rm.mu.RUnlock()

		if callback != nil {
			callback(rr)
		}

		if rm.verbose {
			log.Printf("✅ 请求响应匹配成功: %s -> %s (耗时: %v)",
				rr.Request.Command, rm.extractShortResponse(rr.Response), rr.Duration)
		}
	} else {
		// 未匹配的响应
		rm.updateUnmatchedResponseStats()

		if rm.verbose {
			log.Printf("⚠️ 未匹配的响应: %s", rm.extractShortResponse(response))
		}
	}

	return nil
}

// ProcessPacket 处理数据包
func (rm *RedisMonitor) ProcessPacket(data []byte, conn *types.Connection) error {
	if len(data) == 0 {
		return nil
	}

	// 判断是请求还是响应
	if rm.parser.IsRequest(data) {
		return rm.ProcessRequest(data, conn)
	} else if rm.parser.IsResponse(data) {
		return rm.ProcessResponse(data, conn)
	}

	// 无法识别的数据包
	if rm.verbose {
		log.Printf("❓ 无法识别的Redis数据包: %d字节", len(data))
	}

	return nil
}

// GetStats 获取统计信息
func (rm *RedisMonitor) GetStats() *types.Stats {
	rm.stats.mu.RLock()
	defer rm.stats.mu.RUnlock()

	return &types.Stats{
		TotalRequests:     rm.stats.TotalRequests,
		TotalResponses:    rm.stats.TotalResponses,
		SuccessCount:      rm.stats.MatchedPairs - rm.stats.ErrorResponses,
		ErrorCount:        rm.stats.ErrorResponses,
		AvgLatency:        rm.stats.AvgLatency,
		MaxLatency:        rm.stats.MaxLatency,
		MinLatency:        rm.stats.MinLatency,
		ActiveConnections: 0, // 暂不统计
		StartTime:         rm.stats.StartTime,
	}
}

// PrintStats 打印统计信息
func (rm *RedisMonitor) PrintStats() {
	stats := rm.GetStats()
	duration := time.Since(stats.StartTime)

	fmt.Println("\n=== Redis监控统计 ===")
	fmt.Printf("运行时间: %v\n", duration)
	fmt.Printf("总请求数: %d\n", stats.TotalRequests)
	fmt.Printf("总响应数: %d\n", stats.TotalResponses)
	fmt.Printf("匹配成功: %d\n", rm.stats.MatchedPairs)
	fmt.Printf("未匹配请求: %d\n", rm.stats.UnmatchedReqs)
	fmt.Printf("未匹配响应: %d\n", rm.stats.UnmatchedResps)
	fmt.Printf("错误响应: %d\n", stats.ErrorCount)

	if rm.stats.MatchedPairs > 0 {
		fmt.Printf("平均延迟: %v\n", stats.AvgLatency)
		fmt.Printf("最大延迟: %v\n", stats.MaxLatency)
		fmt.Printf("最小延迟: %v\n", stats.MinLatency)
	}

	if duration > 0 {
		reqRate := float64(stats.TotalRequests) / duration.Seconds()
		fmt.Printf("请求速率: %.2f req/s\n", reqRate)
	}

	fmt.Println("==================")
}

// GetProtocol 获取协议名称
func (rm *RedisMonitor) GetProtocol() string {
	return rm.parser.GetProtocol()
}

// GetDefaultPort 获取默认端口
func (rm *RedisMonitor) GetDefaultPort() int {
	return rm.parser.GetDefaultPort()
}

// 内部方法

// updateRequestStats 更新请求统计
func (rm *RedisMonitor) updateRequestStats() {
	rm.stats.mu.Lock()
	rm.stats.TotalRequests++
	rm.stats.mu.Unlock()
}

// updateResponseStats 更新响应统计
func (rm *RedisMonitor) updateResponseStats(response *types.Message) {
	rm.stats.mu.Lock()
	rm.stats.TotalResponses++

	// 检查是否为错误响应
	if len(response.Data) > 0 && response.Data[0] == '-' {
		rm.stats.ErrorResponses++
	}

	rm.stats.mu.Unlock()
}

// updateMatchStats 更新匹配统计
func (rm *RedisMonitor) updateMatchStats(rr *types.RequestResponse) {
	rm.stats.mu.Lock()
	defer rm.stats.mu.Unlock()

	rm.stats.MatchedPairs++

	// 更新延迟统计
	latency := rr.Duration
	if latency < rm.stats.MinLatency {
		rm.stats.MinLatency = latency
	}
	if latency > rm.stats.MaxLatency {
		rm.stats.MaxLatency = latency
	}

	// 计算平均延迟
	if rm.stats.MatchedPairs == 1 {
		rm.stats.AvgLatency = latency
	} else {
		// 使用累积平均值
		rm.stats.AvgLatency = time.Duration(
			(int64(rm.stats.AvgLatency)*(rm.stats.MatchedPairs-1) + int64(latency)) / rm.stats.MatchedPairs)
	}
}

// updateUnmatchedResponseStats 更新未匹配响应统计
func (rm *RedisMonitor) updateUnmatchedResponseStats() {
	rm.stats.mu.Lock()
	rm.stats.UnmatchedResps++
	rm.stats.mu.Unlock()
}

// extractShortResponse 提取简短的响应内容
func (rm *RedisMonitor) extractShortResponse(response *types.Message) string {
	if response.ParsedData != nil {
		if respStr, ok := response.ParsedData.(string); ok {
			if len(respStr) > 32 {
				return respStr[:32] + "..."
			}
			return respStr
		}
		if respInt, ok := response.ParsedData.(int64); ok {
			return fmt.Sprintf("%d", respInt)
		}
	}
	return response.Command
}
