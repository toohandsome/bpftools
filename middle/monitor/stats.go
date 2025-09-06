// Package monitor - 统计信息更新器
package monitor

import (
	"fmt"
	"sync"
	"time"

	"github.com/myserver/go-server/ebpf/middle/types"
)

// StatsUpdater 统计信息更新器
type StatsUpdater struct {
	stats     *types.Stats
	mu        sync.RWMutex
	lastPrint time.Time
}

// NewStatsUpdater 创建统计更新器
func NewStatsUpdater(stats *types.Stats) *StatsUpdater {
	return &StatsUpdater{
		stats:     stats,
		lastPrint: time.Now(),
	}
}

// formatBytes 格式化字节数
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// RealtimeStatsMonitor 实时统计监控器
type RealtimeStatsMonitor struct {
	stats         *types.Stats
	mu            sync.RWMutex
	lastSnapshot  *types.Stats
	lastUpdate    time.Time
	updateHistory []StatsSnapshot
	maxHistory    int
}

// StatsSnapshot 统计快照
type StatsSnapshot struct {
	Timestamp  time.Time
	Requests   int64
	Responses  int64
	Errors     int64
	BytesSent  int64
	BytesRecv  int64
	AvgLatency time.Duration
}

// NewRealtimeStatsMonitor 创建实时统计监控器
func NewRealtimeStatsMonitor(stats *types.Stats) *RealtimeStatsMonitor {
	return &RealtimeStatsMonitor{
		stats:         stats,
		lastSnapshot:  &types.Stats{},
		lastUpdate:    time.Now(),
		updateHistory: make([]StatsSnapshot, 0, 60), // 保留60个快照
		maxHistory:    60,
	}
}

// Update 更新统计信息
func (rsm *RealtimeStatsMonitor) Update() {
	rsm.mu.Lock()
	defer rsm.mu.Unlock()

	now := time.Now()
	timeDelta := now.Sub(rsm.lastUpdate)

	if timeDelta < time.Second {
		return // 避免过于频繁的更新
	}

	// 创建快照
	snapshot := StatsSnapshot{
		Timestamp:  now,
		Requests:   rsm.stats.TotalRequests,
		Responses:  rsm.stats.TotalResponses,
		Errors:     rsm.stats.ErrorCount,
		BytesSent:  rsm.stats.BytesSent,
		BytesRecv:  rsm.stats.BytesReceived,
		AvgLatency: rsm.stats.AvgLatency,
	}

	// 添加到历史记录
	rsm.updateHistory = append(rsm.updateHistory, snapshot)
	if len(rsm.updateHistory) > rsm.maxHistory {
		rsm.updateHistory = rsm.updateHistory[1:]
	}

	rsm.lastUpdate = now
}

// GetCurrentQPS 获取当前QPS
func (rsm *RealtimeStatsMonitor) GetCurrentQPS() float64 {
	rsm.mu.RLock()
	defer rsm.mu.RUnlock()

	if len(rsm.updateHistory) < 2 {
		return 0
	}

	// 使用最近两个快照计算QPS
	current := rsm.updateHistory[len(rsm.updateHistory)-1]
	previous := rsm.updateHistory[len(rsm.updateHistory)-2]

	timeDiff := current.Timestamp.Sub(previous.Timestamp).Seconds()
	if timeDiff <= 0 {
		return 0
	}

	requestsDiff := current.Requests - previous.Requests
	return float64(requestsDiff) / timeDiff
}

// GetThroughput 获取当前吞吐量 (字节/秒)
func (rsm *RealtimeStatsMonitor) GetThroughput() (float64, float64) {
	rsm.mu.RLock()
	defer rsm.mu.RUnlock()

	if len(rsm.updateHistory) < 2 {
		return 0, 0
	}

	current := rsm.updateHistory[len(rsm.updateHistory)-1]
	previous := rsm.updateHistory[len(rsm.updateHistory)-2]

	timeDiff := current.Timestamp.Sub(previous.Timestamp).Seconds()
	if timeDiff <= 0 {
		return 0, 0
	}

	sentDiff := current.BytesSent - previous.BytesSent
	recvDiff := current.BytesRecv - previous.BytesRecv

	return float64(sentDiff) / timeDiff, float64(recvDiff) / timeDiff
}

// GetErrorRate 获取错误率
func (rsm *RealtimeStatsMonitor) GetErrorRate() float64 {
	rsm.mu.RLock()
	defer rsm.mu.RUnlock()

	if rsm.stats.TotalResponses == 0 {
		return 0
	}

	return float64(rsm.stats.ErrorCount) / float64(rsm.stats.TotalResponses) * 100
}

// GetLatencyPercentiles 获取延迟百分位数 (简化版本)
func (rsm *RealtimeStatsMonitor) GetLatencyPercentiles() map[string]time.Duration {
	rsm.mu.RLock()
	defer rsm.mu.RUnlock()

	// 简化版本，只返回基本统计
	return map[string]time.Duration{
		"min": rsm.stats.MinLatency,
		"avg": rsm.stats.AvgLatency,
		"max": rsm.stats.MaxLatency,
	}
}

// PrintDetailedStats 打印详细统计信息
func (rsm *RealtimeStatsMonitor) PrintDetailedStats() {
	rsm.Update()

	qps := rsm.GetCurrentQPS()
	sentThroughput, recvThroughput := rsm.GetThroughput()
	errorRate := rsm.GetErrorRate()
	latencies := rsm.GetLatencyPercentiles()

	fmt.Printf("\n=== 详细统计信息 ===\n")
	fmt.Printf("当前QPS: %.2f\n", qps)
	fmt.Printf("发送吞吐量: %s/s\n", formatBytes(int64(sentThroughput)))
	fmt.Printf("接收吞吐量: %s/s\n", formatBytes(int64(recvThroughput)))
	fmt.Printf("错误率: %.2f%%\n", errorRate)
	fmt.Printf("延迟统计:\n")
	fmt.Printf("  最小: %v\n", latencies["min"].Round(time.Microsecond))
	fmt.Printf("  平均: %v\n", latencies["avg"].Round(time.Microsecond))
	fmt.Printf("  最大: %v\n", latencies["max"].Round(time.Microsecond))
	fmt.Printf("==================\n\n")
}
