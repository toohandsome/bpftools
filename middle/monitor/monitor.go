// Package monitor 提供中间件监控功能
package monitor

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/myserver/go-server/ebpf/middle/capture"
	"github.com/myserver/go-server/ebpf/middle/config"
	"github.com/myserver/go-server/ebpf/middle/parsers"
	"github.com/myserver/go-server/ebpf/middle/types"
)

// Monitor 中间件监控器
type Monitor struct {
	config    *config.Config
	capture   *capture.Capture
	stats     *types.Stats
	mu        sync.RWMutex
	callbacks []func(*types.RequestResponse)

	// 请求响应匹配
	pendingRequests map[string]*PendingRequest
	requestsMu      sync.RWMutex

	// 多中间件管理器
	middlewareManagers map[string]MiddlewareManager

	// 状态
	isRunning bool
}

// MiddlewareManager 中间件管理器接口
type MiddlewareManager interface {
	GetType() string
	Initialize() error
	StartPeriodicUpdate(ctx context.Context)
	Stop()
	ParseRequest(req *types.Message) (cmd, key, val, valLen string)
	ParseResponse(resp *types.Message) (respStr, respLen string)
	IsErrorResponse(resp *types.Message) bool
	GetCurrentDatabase(conn *types.Connection) string
}

// PendingRequest 待匹配的请求
type PendingRequest struct {
	Message   *types.Message
	Timestamp time.Time
	Timer     *time.Timer
}

// NewMonitor 创建新的监控器
func NewMonitor(cfg *config.Config) (*Monitor, error) {
	// 设置默认值
	cfg.SetDefaults()

	// 创建包捕获器
	cap, err := capture.NewCapture(cfg)
	if err != nil {
		return nil, fmt.Errorf("创建包捕获器失败: %v", err)
	}

	if cfg.Verbose {
		log.Printf("🔍 BPF过滤器: %s", cfg.BuildBPFFilter())
		log.Printf("📊 监控端口: %v", cfg.GetAllPorts())
	}

	m := &Monitor{
		config:             cfg,
		capture:            cap,
		stats:              &types.Stats{StartTime: time.Now()},
		callbacks:          make([]func(*types.RequestResponse), 0),
		pendingRequests:    make(map[string]*PendingRequest),
		middlewareManagers: make(map[string]MiddlewareManager),
	}

	// 初始化多中间件管理器
	m.initializeMiddlewareManagers()

	// 设置包捕获回调
	cap.SetCallback(m.onRequestResponse)

	return m, nil
}

// initializeMiddlewareManagers 初始化中间件管理器
func (m *Monitor) initializeMiddlewareManagers() {
	for name, mwConfig := range m.config.GetEnabledMiddlewares() {
		switch mwConfig.Type {
		case "redis":
			// 创建 Redis 管理器配置
			redisConfig := &config.Config{
				Interface:  m.config.Interface,
				Host:       mwConfig.Host,
				Port:       mwConfig.Port,
				Middleware: mwConfig.Type,
				Mode:       m.config.Mode,
				Verbose:    m.config.Verbose,
				Timeout:    m.config.Timeout,
			}

			// 使用新的带中间件配置的构造函数
			redisManager := parsers.NewRedisClientManagerWithMiddleware(redisConfig, mwConfig)
			if err := redisManager.Initialize(); err != nil {
				if m.config.Verbose {
					log.Printf("⚠️ 无法初始化Redis管理器 [%s]: %v", name, err)
				}
			} else {
				m.middlewareManagers[name] = &RedisManagerAdapter{redisManager}
				if m.config.Verbose {
					log.Printf("✅ Redis管理器 [%s] 初始化成功: %s:%d", name, mwConfig.Host, mwConfig.Port)
					// 显示配置信息
					if mwConfig.Username != "" {
						log.Printf("  ℹ️ 使用用户名: %s", mwConfig.Username)
					}
					if mwConfig.Password != "" {
						log.Printf("  ℹ️ 使用密码认证: ****")
					}
					if mwConfig.Database != 0 {
						log.Printf("  ℹ️ 默认数据库: %d", mwConfig.Database)
					}
					if mwConfig.RedisCliPath != "" && mwConfig.RedisCliPath != "redis-cli" {
						log.Printf("  ℹ️ Redis CLI路径: %s", mwConfig.RedisCliPath)
					}
				}
			}

		case "postgres":
			// TODO: 实现PostgreSQL管理器
			if m.config.Verbose {
				// log.Printf("🚧 PostgreSQL管理器 [%s] 尚未实现", name)
			}

		case "sqlserver":
			// TODO: 实现SQL Server管理器
			if m.config.Verbose {
				// log.Printf("🚧 SQL Server管理器 [%s] 尚未实现", name)
			}

		case "minio":
			// TODO: 实现MinIO管理器
			if m.config.Verbose {
				// log.Printf("🚧 MinIO管理器 [%s] 尚未实现", name)
			}

		case "rocketmq":
			// TODO: 实现RocketMQ管理器
			if m.config.Verbose {
				// log.Printf("🚧 RocketMQ管理器 [%s] 尚未实现", name)
			}

		default:
			// log.Printf("⚠️ 不支持的中间件类型: %s [%s]", mwConfig.Type, name)
		}
	}
}

// RedisManagerAdapter Redis管理器适配器
type RedisManagerAdapter struct {
	*parsers.RedisClientManager
}

func (r *RedisManagerAdapter) GetType() string {
	return "redis"
}

func (r *RedisManagerAdapter) ParseRequest(req *types.Message) (cmd, key, val, valLen string) {
	return r.RedisClientManager.ParseRedisRequest(req)
}

func (r *RedisManagerAdapter) ParseResponse(resp *types.Message) (respStr, respLen string) {
	return r.RedisClientManager.ParseRedisResponse(resp)
}

func (r *RedisManagerAdapter) IsErrorResponse(resp *types.Message) bool {
	return r.RedisClientManager.IsRedisErrorResponse(resp)
}

func (r *RedisManagerAdapter) GetCurrentDatabase(conn *types.Connection) string {
	return r.RedisClientManager.GetCurrentDatabase(conn)
}

// Start 启动监控
func (m *Monitor) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.isRunning {
		m.mu.Unlock()
		return fmt.Errorf("监控器已经在运行中")
	}
	m.isRunning = true
	m.mu.Unlock()

	if m.config.Verbose {
		log.Printf("启动 %s 中间件监控...", m.config.Middleware)
	}

	// 启动请求清理器
	go m.startRequestCleaner(ctx)

	// 启动所有中间件管理器的定时更新
	for name, manager := range m.middlewareManagers {
		if m.config.Verbose {
			log.Printf("⚙️ 启动中间件管理器: %s (%s)", name, manager.GetType())
		}
		manager.StartPeriodicUpdate(ctx)
	}

	// 启动包捕获
	return m.capture.Start(ctx)
}

// Stop 停止监控
func (m *Monitor) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.isRunning {
		return
	}

	m.isRunning = false

	if m.capture != nil {
		m.capture.Stop()
	}

	// 停止所有中间件管理器
	for name, manager := range m.middlewareManagers {
		if m.config.Verbose {
			log.Printf("⏹️ 停止中间件管理器: %s", name)
		}
		manager.Stop()
	}

	// 清理待匹配的请求
	m.requestsMu.Lock()
	for id, pending := range m.pendingRequests {
		if pending.Timer != nil {
			pending.Timer.Stop()
		}
		delete(m.pendingRequests, id)
	}
	m.requestsMu.Unlock()

	if m.config.Verbose {
		log.Println("监控已停止")
	}
}

// SetCallback 设置请求响应回调
func (m *Monitor) SetCallback(callback func(*types.RequestResponse)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callbacks = append(m.callbacks, callback)
}

// onRequestResponse 处理请求响应事件
func (m *Monitor) onRequestResponse(rr *types.RequestResponse) {

	// 通知所有回调
	m.notifyCallbacks(rr)

	// 打印监控信息
	m.printMonitorInfo(rr)

}

// startRequestCleaner 启动请求清理器
func (m *Monitor) startRequestCleaner(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.cleanupExpiredRequests()
		}
	}
}

// cleanupExpiredRequests 清理过期的请求
func (m *Monitor) cleanupExpiredRequests() {
	m.requestsMu.Lock()
	defer m.requestsMu.Unlock()

	now := time.Now()
	for id, pending := range m.pendingRequests {
		if now.Sub(pending.Timestamp) > m.config.Timeout*2 {
			if pending.Timer != nil {
				pending.Timer.Stop()
			}
			delete(m.pendingRequests, id)
		}
	}
}

// notifyCallbacks 通知所有回调
func (m *Monitor) notifyCallbacks(rr *types.RequestResponse) {
	m.mu.RLock()
	callbacks := make([]func(*types.RequestResponse), len(m.callbacks))
	copy(callbacks, m.callbacks)
	m.mu.RUnlock()

	for _, callback := range callbacks {
		callback(rr)
	}
}

// printMonitorInfo 打印监控信息 - 使用特定格式输出
func (m *Monitor) printMonitorInfo(rr *types.RequestResponse) {
	if rr.Request != nil && rr.Response != nil {
		// 构造输出格式: db:cmd-key-val-valLen-resp-respLen-time-clientip-clientport
		output := m.formatRequestResponse(rr)
		if output != "" {
			// log.Printf("%s", output)
		}

	} else if rr.Request != nil {

	} else if rr.Response != nil {

	} else {
		// log.Printf("⚠️ 无效的请求响应对: Request=%v, Response=%v", rr.Request != nil, rr.Response != nil)
	}
}

// formatRequestResponse 格式化请求响应为指定格式
func (m *Monitor) formatRequestResponse(rr *types.RequestResponse) string {
	if rr.Request == nil || rr.Response == nil {
		return ""
	}

	// 根据端口去匹配中间件类型
	middlewareType := m.detectMiddlewareType(rr.Connection)

	switch middlewareType {
	case "redis":
		return m.formatRedisRequestResponse(rr)
	case "postgres":
		// TODO: 实现PostgreSQL格式化
		return m.formatGenericRequestResponse(rr, middlewareType)
	case "sqlserver":
		// TODO: 实现SQL Server格式化
		return m.formatGenericRequestResponse(rr, middlewareType)
	case "minio":
		// TODO: 实现MinIO格式化
		return m.formatGenericRequestResponse(rr, middlewareType)
	case "rocketmq":
		// TODO: 实现RocketMQ格式化
		return m.formatGenericRequestResponse(rr, middlewareType)
	default:
		return m.formatGenericRequestResponse(rr, "unknown")
	}
}

// detectMiddlewareType 根据连接信息检测中间件类型
func (m *Monitor) detectMiddlewareType(conn *types.Connection) string {
	if conn == nil {
		return "unknown"
	}

	// 提取端口号
	port := m.extractPortFromConnection(conn)
	if port == 0 {
		return "unknown"
	}

	// 根据端口匹配中间件类型
	for _, mwConfig := range m.config.GetEnabledMiddlewares() {
		if mwConfig.Port == port {
			return mwConfig.Type
		}
	}

	// 兼容性处理：检查旧配置
	if m.config.Port == port && m.config.Middleware != "" {
		return m.config.Middleware
	}

	return "unknown"
}

// extractPortFromConnection 从连接信息中提取端口号
func (m *Monitor) extractPortFromConnection(conn *types.Connection) int {
	// 从本地或远程地址中提取端口
	addresses := []string{conn.LocalAddr, conn.RemoteAddr}

	for _, addr := range addresses {
		if addr != "" {
			parts := strings.Split(addr, ":")
			if len(parts) == 2 {
				if port, err := strconv.Atoi(parts[1]); err == nil {
					// 检查是否为已配置的端口
					for _, p := range m.config.GetAllPorts() {
						if p == port {
							return port
						}
					}
					// 兼容性检查
					if port == m.config.Port {
						return port
					}
				}
			}
		}
	}

	return 0
}

// getMiddlewareManagerByType 根据类型获取中间件管理器
func (m *Monitor) getMiddlewareManagerByType(middlewareType string) MiddlewareManager {
	for _, manager := range m.middlewareManagers {
		if manager.GetType() == middlewareType {
			return manager
		}
	}
	return nil
}

// formatRedisRequestResponse 格式化Redis请求响应
func (m *Monitor) formatRedisRequestResponse(rr *types.RequestResponse) string {
	// 首先检查是否有有效的解析数据
	if rr.Request == nil || rr.Response == nil {
		return ""
	}

	// 尝试使用高级Redis解析器的数据结构
	var cmd, key, val, valLen, resp, respLen, dbNum string
	clientIP, clientPort := m.getClientInfo(rr.Connection)

	// 检查请求的ParsedData类型
	if parsedCmd, ok := rr.Request.ParsedData.(*parsers.RedisParsedCommand); ok {
		// 使用高级解析器的数据结构
		cmd = strings.ToLower(parsedCmd.Command)
		key = m.truncateStringWithDefault(parsedCmd.Key, 16, "-")
		val = m.truncateStringWithDefault(parsedCmd.Value, 16, "-")
		if parsedCmd.Value != "" {
			valLen = fmt.Sprintf("%db", len(parsedCmd.Value))
		} else {
			valLen = "0b"
		}
		dbNum = parsedCmd.Database
		if dbNum == "" {
			dbNum = "0"
		}
	} else {
		// 回退到传统解析器格式
		redisManager := m.getMiddlewareManagerByType("redis")
		if redisManager != nil {
			cmd, key, val, valLen = redisManager.ParseRequest(rr.Request)
			dbNum = redisManager.GetCurrentDatabase(rr.Connection)
		} else {
			cmd = strings.ToLower(rr.Request.Command)
			key = "-"
			val = "-"
			valLen = "0b"
			dbNum = "0"
			// 调试信息：请求ParsedData类型
			if m.config.Verbose {
				// log.Printf("⚠️ 请求ParsedData类型不匹配: %T", rr.Request.ParsedData)
			}
		}
	}

	// 检查响应的ParsedData类型
	if parsedResp, ok := rr.Response.ParsedData.(*parsers.RedisParsedResponse); ok {
		// 使用高级解析器的响应数据
		resp = m.truncateStringWithDefault(parsedResp.Content, 16, "-")
		respLen = fmt.Sprintf("%db", len(parsedResp.Content))

	} else {
		// 回退到传统解析器格式
		redisManager := m.getMiddlewareManagerByType("redis")
		if redisManager != nil {
			resp, respLen = redisManager.ParseResponse(rr.Response)
		} else {
			resp = "-"
			respLen = "0b"
		}
	}

	// 确保时间为正值（修复负数时间问题）
	timestamp := rr.Duration.Nanoseconds()
	if timestamp < 0 {
		// 如果时间为负，可能是时间戳顺序有问题，使用绝对值
		timestamp = -timestamp
		if m.config.Verbose {
			// log.Printf("⚠️ 检测到负数时间，已修正: %dns", timestamp)
		}
	}

	// 智能时间格式化
	timeStr := m.formatDuration(rr.Duration)

	// 构造格式: db:cmd-key-val-valLen-resp-respLen-time-clientip:clientport
	return fmt.Sprintf("redisMonitorInfo: %s:%s-%s-%s-%s-%s-%s-%s-%s:%s",
		dbNum, cmd, key, val, valLen, resp, respLen, timeStr, clientIP, clientPort)
}

// formatGenericRequestResponse 通用格式化方法
func (m *Monitor) formatGenericRequestResponse(rr *types.RequestResponse, middlewareType string) string {
	// 时间（纳秒）
	timestamp := rr.Duration.Nanoseconds()

	// 客户端 IP 和 端口
	clientIP, clientPort := m.getClientInfo(rr.Connection)

	// 通用格式: middleware:cmd-size-time-clientip-clientport
	return fmt.Sprintf("reidsMonitorInfo: %s:%s-%db-%dns-%s-%s",
		middlewareType, rr.Request.Command, rr.Request.Size, timestamp, clientIP, clientPort)
}

// getClientInfo 获取客户端信息
func (m *Monitor) getClientInfo(conn *types.Connection) (ip, port string) {
	ip = "-"
	port = "-"

	if conn != nil {
		// 根据方向判断客户端
		var clientAddr string
		if conn.Direction == types.DirectionOutbound {
			// 客户端模式：本地地址是客户端
			clientAddr = conn.LocalAddr
		} else {
			// 服务端模式：远程地址是客户端
			clientAddr = conn.RemoteAddr
		}

		// 解析 IP:PORT
		parts := strings.Split(clientAddr, ":")
		if len(parts) == 2 {
			ip = parts[0]
			port = parts[1]
		}
	}

	return ip, port
}

// truncateStringWithDefault 截断字符串并设置默认值
func (m *Monitor) truncateStringWithDefault(s string, maxLen int, defaultVal string) string {
	if s == "" {
		return defaultVal
	}
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

// formatDuration 智能格式化时间间隔
func (m *Monitor) formatDuration(d time.Duration) string {
	if d < 0 {
		d = -d // 使用绝对值
	}

	// 根据时间大小选择合适的单位
	if d >= time.Second {
		// 大于等于1秒，显示秒
		seconds := float64(d) / float64(time.Second)
		if seconds >= 1000 {
			// 大于1000秒，显示分钟
			minutes := seconds / 60
			return fmt.Sprintf("%.1fm", minutes)
		}
		return fmt.Sprintf("%.3fs", seconds)
	} else if d >= time.Millisecond {
		// 1毫秒到999毫秒，显示毫秒
		ms := float64(d) / float64(time.Millisecond)
		return fmt.Sprintf("%.1fms", ms)
	} else if d >= time.Microsecond {
		// 1微秒到999微秒，显示微秒
		us := float64(d) / float64(time.Microsecond)
		return fmt.Sprintf("%.1fμs", us)
	} else {
		// 小于1微秒，显示纳秒
		return fmt.Sprintf("%dns", d.Nanoseconds())
	}
}
