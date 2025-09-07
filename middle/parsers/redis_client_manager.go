// Package parsers - Redis客户端管理器
package parsers

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/myserver/go-server/ebpf/middle/config"
	"github.com/myserver/go-server/ebpf/middle/types"
)

// RedisClientManager Redis客户端管理器，负责处理Redis特定的功能
type RedisClientManager struct {
	config         *config.Config
	middlewareConf *config.MiddlewareConfig // Redis中间件特定配置
	verbose        bool

	// Redis数据库追踪（按连接）
	currentDBs map[string]string // 连接ID -> 数据库编号
	dbMu       sync.RWMutex

	// Redis进程和客户端信息追踪
	processInfo *RedisProcessInfo

	// 定时更新器控制
	updateTicker *time.Ticker
	stopChan     chan struct{}
	mu           sync.RWMutex
}

// RedisProcessInfo Redis进程信息
type RedisProcessInfo struct {
	PID       int
	ClientMap map[string]int // 连接地址 -> 数据库编号
	mu        sync.RWMutex
}

// NewRedisClientManager 创建Redis客户端管理器
func NewRedisClientManager(cfg *config.Config) *RedisClientManager {
	return &RedisClientManager{
		config:     cfg,
		verbose:    cfg.Verbose,
		currentDBs: make(map[string]string),
		processInfo: &RedisProcessInfo{
			ClientMap: make(map[string]int),
		},
		stopChan: make(chan struct{}),
	}
}

// NewRedisClientManagerWithMiddleware 使用中间件配置创建Redis客户端管理器
func NewRedisClientManagerWithMiddleware(cfg *config.Config, middlewareConf *config.MiddlewareConfig) *RedisClientManager {
	return &RedisClientManager{
		config:         cfg,
		middlewareConf: middlewareConf,
		verbose:        cfg.Verbose,
		currentDBs:     make(map[string]string),
		processInfo: &RedisProcessInfo{
			ClientMap: make(map[string]int),
		},
		stopChan: make(chan struct{}),
	}
}

// Initialize 初始化Redis客户端管理器
func (rcm *RedisClientManager) Initialize() error {
	// 查找Redis进程
	pid, err := rcm.findRedisProcess()
	if err != nil {
		return fmt.Errorf("找不到Redis进程: %v", err)
	}

	rcm.processInfo.PID = pid

	if rcm.verbose {
		// log.Printf("🔍 找到Redis进程 PID: %d", pid)
	}

	// 尝试获取初始的客户端信息
	if err := rcm.queryRedisClientInfo(); err != nil {
		if rcm.verbose {
			// log.Printf("⚠️ 获取Redis客户端信息失败: %v", err)
		}
	}

	return nil
}

// StartPeriodicUpdate 启动定时更新Redis客户端信息
func (rcm *RedisClientManager) StartPeriodicUpdate(ctx context.Context) {
	rcm.mu.Lock()
	if rcm.updateTicker != nil {
		rcm.mu.Unlock()
		return // 已经启动
	}

	rcm.updateTicker = time.NewTicker(time.Minute) // 每分钟更新一次
	rcm.mu.Unlock()

	go func() {
		defer rcm.updateTicker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-rcm.stopChan:
				return
			case <-rcm.updateTicker.C:
				if err := rcm.queryRedisClientInfo(); err != nil {
					if rcm.verbose {
						// log.Printf("⚠️ 定时更新Redis客户端信息失败: %v", err)
					}
				} else if rcm.verbose {
					// log.Printf("✅ 成功更新Redis客户端映射关系")
				}
			}
		}
	}()
}

// Stop 停止定时更新
func (rcm *RedisClientManager) Stop() {
	rcm.mu.Lock()
	defer rcm.mu.Unlock()

	if rcm.updateTicker != nil {
		close(rcm.stopChan)
		rcm.updateTicker = nil
	}
}

// SetCurrentDatabase 设置当前连接的数据库编号
func (rcm *RedisClientManager) SetCurrentDatabase(conn *types.Connection, db string) {
	if conn == nil {
		return
	}

	connKey := rcm.getConnectionKey(conn)
	rcm.dbMu.Lock()
	rcm.currentDBs[connKey] = db
	rcm.dbMu.Unlock()
}

// GetCurrentDatabase 获取当前连接的数据库编号
func (rcm *RedisClientManager) GetCurrentDatabase(conn *types.Connection) string {
	if conn == nil {
		return "0" // 默认数据库
	}

	connKey := rcm.getConnectionKey(conn)
	rcm.dbMu.RLock()
	db, exists := rcm.currentDBs[connKey]
	rcm.dbMu.RUnlock()

	if !exists {
		// 尝试智能检测数据库编号
		detectedDB := rcm.detectDatabaseFromConnection(conn)
		if detectedDB != "0" {
			rcm.SetCurrentDatabase(conn, detectedDB)
			return detectedDB
		}
		return "0" // 默认数据库
	}
	return db
}

// ParseRedisRequest 解析Redis请求，提取数据库相关信息
func (rcm *RedisClientManager) ParseRedisRequest(req *types.Message) (cmd, key, val, valLen string) {
	cmd = strings.ToLower(req.Command)
	key = "-"
	val = "-"
	valLen = "0b"

	if req.ParsedData != nil {
		if args, ok := req.ParsedData.([]string); ok && len(args) > 0 {
			cmd = strings.ToLower(args[0])

			// 提取 key
			if len(args) > 1 {
				key = rcm.truncateString(args[1], 16)
			}

			// 提取 value（对于 SET 命令）
			if len(args) > 2 && strings.ToUpper(args[0]) == "SET" {
				originalVal := args[2]
				val = rcm.truncateString(originalVal, 16)
				valLen = fmt.Sprintf("%db", len(originalVal))
			}

			// 对于 SELECT 命令，更新数据库编号
			if len(args) > 1 && strings.ToUpper(args[0]) == "SELECT" {
				rcm.SetCurrentDatabase(req.Connection, args[1])

			}
		}
	}

	return cmd, key, val, valLen
}

// ParseRedisResponse 解析Redis响应
func (rcm *RedisClientManager) ParseRedisResponse(resp *types.Message) (respStr, respLen string) {
	respStr = "-"
	respLen = "0b"

	if resp.ParsedData != nil {
		if respData, ok := resp.ParsedData.(string); ok {
			respStr = rcm.truncateString(respData, 16)
			respLen = fmt.Sprintf("%db", len(respData))
		}
	}

	return respStr, respLen
}

// IsRedisErrorResponse 判断是否为Redis错误响应
func (rcm *RedisClientManager) IsRedisErrorResponse(resp *types.Message) bool {
	// Redis错误响应以-开头
	return len(resp.Data) > 0 && resp.Data[0] == '-'
}

// detectDatabaseFromConnection 从连接信息智能检测数据库编号
func (rcm *RedisClientManager) detectDatabaseFromConnection(conn *types.Connection) string {
	if conn == nil {
		return "?"
	}

	// 优先级 1: 从系统信息检测（Redis CLIENT LIST）
	if systemDB := rcm.tryDetectDatabaseFromSystemInfo(conn); systemDB != "" {
		return systemDB
	}

	// 优先级 2: 检查是否有最近的 SELECT 命令记录
	recentDB := rcm.getRecentDatabaseSelection(conn)
	if recentDB != "" {
		return recentDB
	}

	// 无法确定数据库，返回未知标识
	// if rcm.verbose {
	// 	// log.Printf("⚠️ 无法确定连接 %s -> %s 的数据库编号",
	// 		conn.LocalAddr, conn.RemoteAddr)
	// 	// log.Printf("💡 解决方案：")
	// 	// log.Printf("   1. 在监控程序启动后执行SELECT命令")
	// 	// log.Printf("   2. 重新连接Redis客户端")
	// 	// log.Printf("   3. 使用redis-cli -n X指定数据库")
	// }

	return "?" // 使用'?'表示数据库未知，提醒用户这不是确定的值
}

// tryDetectDatabaseFromSystemInfo 尝试从系统信息检测数据库
func (rcm *RedisClientManager) tryDetectDatabaseFromSystemInfo(conn *types.Connection) string {
	if rcm.processInfo == nil || conn == nil {
		return ""
	}

	// 构造可能的地址格式
	clientAddr := ""
	if conn.Direction == types.DirectionOutbound {
		clientAddr = conn.LocalAddr
	} else {
		clientAddr = conn.RemoteAddr
	}

	// 查找客户端映射
	rcm.processInfo.mu.RLock()
	db, exists := rcm.processInfo.ClientMap[clientAddr]
	rcm.processInfo.mu.RUnlock()

	if exists {
		if rcm.verbose {
			// log.Printf("🎯 从系统信息检测到数据库: %s -> 数据库 %d", clientAddr, db)
		}
		return fmt.Sprintf("%d", db)
	}

	return ""
}

// getRecentDatabaseSelection 获取最近的数据库选择记录
func (rcm *RedisClientManager) getRecentDatabaseSelection(conn *types.Connection) string {
	if conn == nil {
		return ""
	}

	connKey := rcm.getConnectionKey(conn)
	rcm.dbMu.RLock()
	db, exists := rcm.currentDBs[connKey]
	rcm.dbMu.RUnlock()

	if exists && db != "0" {
		if rcm.verbose {
			// log.Printf("🔍 从历史记录中找到数据库: 连接 %s 使用数据库 %s", connKey, db)
		}
		return db
	}

	return "" // 没有找到历史记录
}

// getConnectionKey 获取连接唯一标识
func (rcm *RedisClientManager) getConnectionKey(conn *types.Connection) string {
	if conn == nil {
		return "unknown"
	}
	return fmt.Sprintf("%s-%s", conn.LocalAddr, conn.RemoteAddr)
}

// truncateString 截断字符串到指定长度
func (rcm *RedisClientManager) truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

// findRedisProcess 查找Redis进程
func (rcm *RedisClientManager) findRedisProcess() (int, error) {
	// 方法1: 通过端口查找
	netstatCmd := fmt.Sprintf("netstat -tlnp 2>/dev/null | grep ':%d ' | awk '{print $7}' | cut -d'/' -f1 | head -1", rcm.config.Port)
	output, err := rcm.executeCommand(netstatCmd)
	if err == nil && len(output) > 0 {
		if pid, parseErr := strconv.Atoi(strings.TrimSpace(output)); parseErr == nil && pid > 0 {
			return pid, nil
		}
	}

	// 方法2: 通过进程名查找
	pgrepCmd := "pgrep redis-server | head -1"
	output, err = rcm.executeCommand(pgrepCmd)
	if err == nil && len(output) > 0 {
		if pid, parseErr := strconv.Atoi(strings.TrimSpace(output)); parseErr == nil && pid > 0 {
			return pid, nil
		}
	}

	return 0, fmt.Errorf("Redis进程未找到")
}

// executeCommand 执行系统命令
func (rcm *RedisClientManager) executeCommand(cmd string) (string, error) {
	out, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// queryRedisClientInfo 查询Redis客户端信息
func (rcm *RedisClientManager) queryRedisClientInfo() error {
	// 构建redis-cli命令参数
	cmdArgs := rcm.buildRedisCliArgs()
	cmdArgs = append(cmdArgs, "CLIENT", "LIST")

	clientListCmd := strings.Join(cmdArgs, " ") + " 2>/dev/null"
	output, err := rcm.executeCommand(clientListCmd)
	if err != nil {
		return fmt.Errorf("执行CLIENT LIST失败: %v", err)
	}

	// if rcm.verbose {
	// 	// log.Printf("🔍 Redis CLIENT LIST 响应:")
	// 	lines := strings.Split(output, "\n")
	// 	for i, line := range lines {
	// 		if strings.TrimSpace(line) != "" && i < 3 { // 只显示前3行
	// 			// log.Printf("   %s", line)
	// 		}
	// 	}
	// }

	// 解析CLIENT LIST输出，只提取addr和数据库信息
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		if err := rcm.parseClientListLine(line); err != nil && rcm.verbose {
			// log.Printf("⚠️ 解析客户端信息失败: %v", err)
		}
	}

	return nil
}

// buildRedisCliArgs 构建redis-cli命令参数
func (rcm *RedisClientManager) buildRedisCliArgs() []string {
	// 获取redis-cli路径
	redisCliPath := "redis-cli" // 默认值
	if rcm.middlewareConf != nil && rcm.middlewareConf.RedisCliPath != "" {
		redisCliPath = rcm.middlewareConf.RedisCliPath
	}

	// 获取连接参数
	host := rcm.config.Host
	port := rcm.config.Port
	if rcm.middlewareConf != nil {
		if rcm.middlewareConf.Host != "" {
			host = rcm.middlewareConf.Host
		}
		if rcm.middlewareConf.Port != 0 {
			port = rcm.middlewareConf.Port
		}
	}

	// 构建基本参数
	args := []string{redisCliPath, "-h", host, "-p", fmt.Sprintf("%d", port)}

	// 添加认证参数
	if rcm.middlewareConf != nil {
		// 添加用户名（Redis 6.0+）
		if rcm.middlewareConf.Username != "" {
			args = append(args, "--user", rcm.middlewareConf.Username)
		}

		// 添加密码
		if rcm.middlewareConf.Password != "" {
			args = append(args, "-a", rcm.middlewareConf.Password)
		}

		// 添加默认数据库
		if rcm.middlewareConf.Database != 0 {
			args = append(args, "-n", fmt.Sprintf("%d", rcm.middlewareConf.Database))
		}
	}

	return args
}

// parseClientListLine 解析CLIENT LIST输出的一行
func (rcm *RedisClientManager) parseClientListLine(line string) error {
	// 解析客户端信息行
	// 格式: id=14 addr=192.168.2.11:53790 laddr=192.168.2.226:6379 fd=11 ... db=2 ...

	var addr string
	var db int

	// 使用简单的字符串解析
	parts := strings.Split(line, " ")
	for _, part := range parts {
		if strings.HasPrefix(part, "addr=") {
			addr = strings.TrimPrefix(part, "addr=")
		} else if strings.HasPrefix(part, "db=") {
			if dbVal, err := strconv.Atoi(strings.TrimPrefix(part, "db=")); err == nil {
				db = dbVal
			}
		}
	}

	if addr != "" {
		rcm.processInfo.mu.Lock()
		rcm.processInfo.ClientMap[addr] = db
		rcm.processInfo.mu.Unlock()

		// if rcm.verbose {
		// 	// log.Printf("✅ 找到客户端映射: addr=%s db=%d", addr, db)
		// }
	}

	return nil
}
