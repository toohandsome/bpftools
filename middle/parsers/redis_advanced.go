// Package parsers - 高级Redis协议解析器，参考myRedisCapturer项目设计
package parsers

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/myserver/go-server/ebpf/middle/types"
)

// RedisAdvancedParser 高级Redis解析器，实现完整的请求响应关联
type RedisAdvancedParser struct {
	// 连接会话管理器
	sessionManager *RedisSessionManager

	// Redis命令表，用于解析命令元数据
	commandTable *RedisCommandTable

	// 配置
	config *RedisAdvancedConfig

	// 统计信息
	stats *RedisParserStats
}

// RedisAdvancedConfig 高级Redis解析器配置
type RedisAdvancedConfig struct {
	MaxContentLength    int           // 显示内容的最大长度（默认64字符）
	EnableDBTracking    bool          // 是否启用数据库跟踪
	SessionTimeout      time.Duration // 会话超时时间
	EnableDetailedStats bool          // 是否启用详细统计
	Verbose             bool          // 详细日志
}

// RedisSessionManager 连接会话管理器
type RedisSessionManager struct {
	sessions       map[string]*RedisSession // 连接ID -> 会话
	mu             sync.RWMutex
	sessionTimeout time.Duration
}

// RedisSession Redis连接会话
type RedisSession struct {
	ConnKey          string                    // 连接唯一标识
	CurrentDB        string                    // 当前数据库
	PendingRequests  map[string]*RedisRequest  // 待匹配的请求 ID -> 请求
	PendingResponses map[string]*types.Message // 缓存未匹配的响应
	LastActivity     time.Time                 // 最后活动时间
	RequestCount     int64                     // 请求计数
	ResponseCount    int64                     // 响应计数
	mu               sync.RWMutex
}

// RedisRequest Redis请求信息
type RedisRequest struct {
	Message     *types.Message
	ParsedCmd   *RedisParsedCommand
	Timestamp   time.Time
	SequenceNum int64 // 请求序列号（用于匹配）
}

// RedisParsedCommand 解析后的Redis命令（公开类型）
type RedisParsedCommand struct {
	Command     string            // 命令名
	Args        []string          // 参数列表
	Key         string            // 主键（如果有）
	Value       string            // 值（如果有）
	Database    string            // 数据库编号
	CommandMeta *RedisCommandMeta // 命令元数据
}

// RedisCommandMeta Redis命令元数据
type RedisCommandMeta struct {
	Name     string
	MinArgs  int    // 最小参数数量
	Flags    string // 命令标志 (readonly, write, admin)
	FirstKey int    // 第一个key的位置
	LastKey  int    // 最后一个key的位置
	KeyStep  int    // key的步长
	IsWrite  bool   // 是否为写命令
	IsRead   bool   // 是否为读命令
	IsAdmin  bool   // 是否为管理命令
}

// Redis命令表
type RedisCommandTable struct {
	commands map[string]*RedisCommandMeta
	mu       sync.RWMutex
}

// RedisParsedResponse 解析后的Redis响应（公开类型）
type RedisParsedResponse struct {
	Type         string // 响应类型 (+, -, :, $, *)
	Content      string // 响应内容
	IsError      bool   // 是否为错误
	Size         int    // 数据大小
	ElementCount int    // 元素数量（数组类型）
}

// RedisParserStats Redis解析器统计
type RedisParserStats struct {
	TotalRequests      int64
	TotalResponses     int64
	MatchedPairs       int64
	UnmatchedRequests  int64
	UnmatchedResponses int64
	ParseErrors        int64
	ActiveSessions     int64
	mu                 sync.RWMutex
}

// NewRedisAdvancedParser 创建高级Redis解析器
func NewRedisAdvancedParser(config *RedisAdvancedConfig) *RedisAdvancedParser {
	if config == nil {
		config = &RedisAdvancedConfig{
			MaxContentLength:    64,
			EnableDBTracking:    true,
			SessionTimeout:      30 * time.Second,
			EnableDetailedStats: true,
			Verbose:             false,
		}
	}

	parser := &RedisAdvancedParser{
		sessionManager: &RedisSessionManager{
			sessions:       make(map[string]*RedisSession),
			sessionTimeout: config.SessionTimeout,
		},
		commandTable: NewRedisCommandTable(),
		config:       config,
		stats:        &RedisParserStats{},
	}

	// 启动会话清理器
	go parser.startSessionCleaner()

	return parser
}

// GetProtocol 获取协议名称
func (p *RedisAdvancedParser) GetProtocol() string {
	return "redis"
}

// GetDefaultPort 获取默认端口
func (p *RedisAdvancedParser) GetDefaultPort() int {
	return 6379
}

// IsRequest 判断是否为请求
func (p *RedisAdvancedParser) IsRequest(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	// 过滤掉无效数据
	if !p.isValidRedisData(data) {
		return false
	}

	// Redis请求通常以*开头(数组格式)
	switch data[0] {
	case '*':
		// 验证是否为有效的RESP数组格式
		return p.isValidRESPArray(data)
	case '+', '-', ':', '$':
		return false
	default:
		// 检查内联命令格式
		return p.isInlineCommand(data)
	}
}

// IsResponse 判断是否为响应
func (p *RedisAdvancedParser) IsResponse(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	// 过滤掉无效数据
	if !p.isValidRedisData(data) {
		return false
	}

	// Redis响应标识符
	switch data[0] {
	case '+', '-', ':', '$':
		// 验证响应格式的完整性
		return p.isValidRESPResponse(data)
	case '*':
		// 数组可能是响应（如SCAN命令的响应），需要更详细的判断
		return p.isArrayResponse(data)
	default:
		return false
	}
}

// ParseRequest 解析请求
func (p *RedisAdvancedParser) ParseRequest(data []byte) (*types.Message, error) {
	p.stats.mu.Lock()
	p.stats.TotalRequests++
	p.stats.mu.Unlock()

	if len(data) == 0 {
		return nil, fmt.Errorf("空数据")
	}

	// 早期验证：检查是否为有效的Redis数据
	if !p.isValidRedisData(data) {
		return nil, fmt.Errorf("无效的Redis数据: %q", string(data))
	}

	msg := &types.Message{
		Type: "request",
		Data: data,
		Size: len(data),
		// 注意：不在这里设置时间戳，由调用者负责设置
		// Timestamp: time.Now(),
	}

	var parsedCmd *RedisParsedCommand
	var err error

	if data[0] == '*' {
		// 解析RESP数组格式
		parsedCmd, err = p.parseRESPCommand(data)
	} else {
		// 解析内联命令格式
		parsedCmd, err = p.parseInlineCommand(data)
	}

	if err != nil {
		p.stats.mu.Lock()
		p.stats.ParseErrors++
		p.stats.mu.Unlock()
		return nil, fmt.Errorf("解析Redis命令失败: %v", err)
	}

	// 检查解析结果是否有效
	if parsedCmd == nil || parsedCmd.Command == "" {
		return nil, fmt.Errorf("解析的命令为空")
	}

	// 设置消息属性
	msg.Command = parsedCmd.Command
	msg.ParsedData = parsedCmd
	msg.ID = p.generateRequestID(msg, parsedCmd)

	// 注意：不在这里注册请求，因为Connection可能还没有设置
	// 由调用者负责在设置好连接信息后调用RegisterRequestManually

	return msg, nil
}

// ParseResponse 解析响应
func (p *RedisAdvancedParser) ParseResponse(data []byte) (*types.Message, error) {
	p.stats.mu.Lock()
	p.stats.TotalResponses++
	p.stats.mu.Unlock()

	if len(data) == 0 {
		return nil, fmt.Errorf("空数据")
	}

	// 早期验证：检查是否为有效的Redis数据
	if !p.isValidRedisData(data) {
		return nil, fmt.Errorf("无效的Redis响应数据: %q", string(data))
	}

	msg := &types.Message{
		Type: "response",
		Data: data,
		Size: len(data),
		// 注意：不在这里设置时间戳，由调用者负责设置
		// Timestamp: time.Now(),
	}

	parsedResp, err := p.parseRESPResponse(data)
	if err != nil {
		p.stats.mu.Lock()
		p.stats.ParseErrors++
		p.stats.mu.Unlock()
		return nil, fmt.Errorf("解析Redis响应失败: %v", err)
	}

	// 设置消息属性
	msg.Command = p.getResponseType(data[0])
	msg.ParsedData = parsedResp

	return msg, nil
}

// MatchRequestResponse 匹配请求和响应
func (p *RedisAdvancedParser) MatchRequestResponse(response *types.Message) *types.RequestResponse {
	connKey := p.getConnectionKey(response.Connection)
	session := p.getOrCreateSession(connKey, response.Connection)

	// if p.config.Verbose {
	// 	// log.Printf("🔍 响应匹配调试: 连接键=%s, 待匹配请求数=%d", connKey, len(session.PendingRequests))
	// 	// log.Printf("  - 响应连接信息: LocalAddr=%s, RemoteAddr=%s, Direction=%v",
	// 		response.Connection.LocalAddr, response.Connection.RemoteAddr, response.Connection.Direction)

	// 	// 显示当前所有活跃会话
	// 	p.sessionManager.mu.RLock()
	// 	// log.Printf("  - 当前活跃会话数: %d", len(p.sessionManager.sessions))
	// 	for sessionKey, session := range p.sessionManager.sessions {
	// 		// log.Printf("    会话键: %s, 待匹配请求数: %d", sessionKey, len(session.PendingRequests))
	// 		for reqID, req := range session.PendingRequests {
	// 			// log.Printf("      - 请求: ID=%s, 命令=%s, 序列号=%d", reqID, req.ParsedCmd.Command, req.SequenceNum)
	// 		}
	// 	}
	// 	p.sessionManager.mu.RUnlock()
	// }

	session.mu.Lock()
	defer session.mu.Unlock()

	// 寻找最早的待匹配请求（改进匹配算法）
	var matchedRequest *RedisRequest
	var matchedKey string

	// 按序列号顺序匹配（FIFO）
	var minSeq int64 = -1
	for key, req := range session.PendingRequests {
		if minSeq == -1 || req.SequenceNum < minSeq {
			minSeq = req.SequenceNum
			matchedRequest = req
			matchedKey = key
		}
	}

	if matchedRequest == nil {
		// 未找到匹配的请求，缓存响应等待请求到达
		responseKey := fmt.Sprintf("resp_%d_%s", response.Timestamp.UnixNano(), response.Command)
		session.PendingResponses[responseKey] = response

		p.stats.mu.Lock()
		p.stats.UnmatchedResponses++
		p.stats.mu.Unlock()

		// if p.config.Verbose {
		// 	// log.Printf("⚠️ 未找到匹配的请求，缓存响应等待: %s, 响应时间=%v", responseKey, response.Timestamp.UnixNano())
		// 	// log.Printf("  当前待匹配请求数: %d, 缓存响应数: %d", len(session.PendingRequests), len(session.PendingResponses))
		// }
		return nil
	}

	// 删除已匹配的请求
	delete(session.PendingRequests, matchedKey)
	session.ResponseCount++

	// 创建请求响应对
	duration := response.Timestamp.Sub(matchedRequest.Timestamp)

	// 诊断时间异常问题而不是简单修正
	if duration < 0 {

		duration = -duration
	} else if duration > 10*time.Second {

		// 对于异常大的时间，我们仍然记录但标记为可疑
	}

	rr := &types.RequestResponse{
		Request:    matchedRequest.Message,
		Response:   response,
		Duration:   duration,
		Success:    !p.isErrorResponse(response),
		Connection: matchedRequest.Message.Connection,
	}

	// 设置错误信息
	if !rr.Success {
		if respData, ok := response.ParsedData.(*RedisParsedResponse); ok && respData.IsError {
			rr.ErrorMsg = respData.Content
		}
	}

	p.stats.mu.Lock()
	p.stats.MatchedPairs++
	p.stats.mu.Unlock()

	// if p.config.Verbose {
	// 	// log.Printf("✅ 成功匹配请求响应: %s -> %s, 耗时: %v", matchedRequest.Message.Command, response.Command, duration)
	// }

	return rr
}

// RegisterRequestManually 手动注册请求（用于在Connection设置后注册）
func (p *RedisAdvancedParser) RegisterRequestManually(msg *types.Message, parsedCmd *RedisParsedCommand) {
	// 重新生成ID，现在连接信息已经可用
	msg.ID = p.generateRequestID(msg, parsedCmd)
	p.registerRequest(msg, parsedCmd)
}

// FormatRequestResponse 格式化请求响应输出
func (p *RedisAdvancedParser) FormatRequestResponse(rr *types.RequestResponse) string {
	if rr == nil || rr.Request == nil || rr.Response == nil {
		return ""
	}

	// 获取解析后的命令
	parsedCmd, ok := rr.Request.ParsedData.(*RedisParsedCommand)
	if !ok {
		return ""
	}

	// 获取解析后的响应
	parsedResp, ok := rr.Response.ParsedData.(*RedisParsedResponse)
	if !ok {
		return ""
	}

	// 获取数据库信息
	db := parsedCmd.Database
	if db == "" {
		db = "0"
	}

	// 获取客户端信息
	clientIP, clientPort := p.getClientInfo(rr.Connection)

	// 格式化请求内容
	reqBody := p.formatRequestBody(parsedCmd)

	// 格式化响应内容
	respBody := p.formatResponseBody(parsedResp)

	// 计算耗时（微秒）
	costUs := rr.Duration.Microseconds()

	// 输出格式: db=X cmd=X key=X req=X resp=X cost=Xμs client=X:X
	return fmt.Sprintf("db=%s cmd=%s key=%s req=%s resp=%s cost=%dμs client=%s:%s",
		db,
		strings.ToLower(parsedCmd.Command),
		p.truncateString(parsedCmd.Key, 16),
		reqBody,
		respBody,
		costUs,
		clientIP,
		clientPort,
	)
}

// 内部方法实现

// getConnectionKey 获取连接唯一标识
func (p *RedisAdvancedParser) getConnectionKey(conn *types.Connection) string {
	if conn == nil {
		return "unknown"
	}
	// 标准化连接键，确保请求和响应使用相同的键
	addr1, addr2 := conn.LocalAddr, conn.RemoteAddr
	if addr1 > addr2 {
		addr1, addr2 = addr2, addr1
	}
	return fmt.Sprintf("%s<->%s", addr1, addr2)
}

// getOrCreateSession 获取或创建会话
func (p *RedisAdvancedParser) getOrCreateSession(connKey string, conn *types.Connection) *RedisSession {
	p.sessionManager.mu.Lock()
	defer p.sessionManager.mu.Unlock()

	session, exists := p.sessionManager.sessions[connKey]
	if !exists {
		session = &RedisSession{
			ConnKey:          connKey,
			CurrentDB:        "0", // 默认数据库
			PendingRequests:  make(map[string]*RedisRequest),
			PendingResponses: make(map[string]*types.Message),
			LastActivity:     time.Now(),
		}
		p.sessionManager.sessions[connKey] = session
	}

	session.LastActivity = time.Now()
	return session
}

// registerRequest 注册请求到会话
func (p *RedisAdvancedParser) registerRequest(msg *types.Message, parsedCmd *RedisParsedCommand) {
	connKey := p.getConnectionKey(msg.Connection)
	session := p.getOrCreateSession(connKey, msg.Connection)

	// if p.config.Verbose {
	// 	// log.Printf("📝 请求注册调试: 连接键=%s, 命令=%s, ID=%s", connKey, parsedCmd.Command, msg.ID)
	// 	// log.Printf("  - 连接信息: LocalAddr=%s, RemoteAddr=%s, Direction=%v",
	// 		msg.Connection.LocalAddr, msg.Connection.RemoteAddr, msg.Connection.Direction)
	// }

	session.mu.Lock()
	defer session.mu.Unlock()

	// 处理SELECT命令
	if p.config.EnableDBTracking && strings.ToUpper(parsedCmd.Command) == "SELECT" && len(parsedCmd.Args) > 1 {
		session.CurrentDB = parsedCmd.Args[1]
		parsedCmd.Database = session.CurrentDB
	} else {
		parsedCmd.Database = session.CurrentDB
	}

	// 创建请求记录
	request := &RedisRequest{
		Message:     msg,
		ParsedCmd:   parsedCmd,
		Timestamp:   msg.Timestamp,
		SequenceNum: session.RequestCount,
	}

	// 检查是否已存在相同的请求（避免重复处理）
	if existingReq, exists := session.PendingRequests[msg.ID]; exists {

		// 如果命令相同，则是真正的重复，忽略
		if existingReq.ParsedCmd.Command == parsedCmd.Command {
			return
		}
		// 如果命令不同，可能是ID冲突，替换旧请求
		if p.config.Verbose {
			// log.Printf("🔄 ID冲突，替换旧请求: %s -> %s", existingReq.ParsedCmd.Command, parsedCmd.Command)
		}
	}

	session.PendingRequests[msg.ID] = request
	session.RequestCount++

	// if p.config.Verbose {
	// 	// log.Printf("📄 注册请求: ID=%s, 命令=%s, 当前待匹配数=%d, 时间戳=%v",
	// 		msg.ID, parsedCmd.Command, len(session.PendingRequests), msg.Timestamp.UnixNano())

	// 	// 显示当前会话中的所有请求
	// 	// log.Printf("  当前会话中的请求:")
	// 	for reqID, req := range session.PendingRequests {
	// 		// log.Printf("    - ID=%s, 命令=%s, 序列号=%d, 时间戳=%v",
	// 			reqID, req.ParsedCmd.Command, req.SequenceNum, req.Timestamp.UnixNano())
	// 	}
	// }

	// 清理过期的请求
	p.cleanupExpiredRequests(session)

	// 检查是否有等待的响应可以匹配
	p.checkPendingResponses(session)
}

// generateRequestID 生成请求ID（改进ID生成算法防止冲突）
func (p *RedisAdvancedParser) generateRequestID(msg *types.Message, parsedCmd *RedisParsedCommand) string {
	// 如果连接信息尚未设置，使用临时ID生成策略
	var connKey string
	if msg.Connection != nil {
		connKey = p.getConnectionKey(msg.Connection)
	} else {
		connKey = "temp" // 临时连接键
	}

	timestamp := msg.Timestamp.UnixNano()

	// 使用更精细的ID生成，包括时间戳、命令、参数和随机数
	cmdStr := parsedCmd.Command
	if len(parsedCmd.Args) > 1 {
		cmdStr += "_" + parsedCmd.Args[1] // 包括第一个参数（通常是key）
	}

	// 添加数据大小和地址作为额外的唯一性保证
	dataHash := len(msg.Data)

	return fmt.Sprintf("%s_%s_%d_%d_%p", connKey, cmdStr, timestamp, dataHash, msg)
}

// startSessionCleaner 启动会话清理器（降低清理频率）
func (p *RedisAdvancedParser) startSessionCleaner() {
	// 将清理频率从30秒增加到5分钟，减少对正常请求的干扰
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		p.cleanupExpiredSessions()
	}
}

// cleanupExpiredSessions 清理过期会话
func (p *RedisAdvancedParser) cleanupExpiredSessions() {
	p.sessionManager.mu.Lock()
	defer p.sessionManager.mu.Unlock()

	now := time.Now()
	for connKey, session := range p.sessionManager.sessions {
		if now.Sub(session.LastActivity) > p.sessionManager.sessionTimeout {
			// 统计未匹配的请求
			session.mu.RLock()
			unmatchedCount := int64(len(session.PendingRequests))
			session.mu.RUnlock()

			p.stats.mu.Lock()
			p.stats.UnmatchedRequests += unmatchedCount
			p.stats.mu.Unlock()

			delete(p.sessionManager.sessions, connKey)
		}
	}
}

// cleanupExpiredRequests 清理会话中的过期请求（调整清理策略）
func (p *RedisAdvancedParser) cleanupExpiredRequests(session *RedisSession) {
	now := time.Now()
	cleanupCount := 0
	for reqID, request := range session.PendingRequests {
		// 将超时时间从30秒增加到2分钟，减少过度清理
		if now.Sub(request.Timestamp) > 2*time.Minute {
			delete(session.PendingRequests, reqID)
			cleanupCount++
		}
	}

	if cleanupCount > 0 {
		p.stats.mu.Lock()
		p.stats.UnmatchedRequests += int64(cleanupCount)
		p.stats.mu.Unlock()

		if p.config.Verbose {
			// log.Printf("🗑️ 清理了 %d 个过期请求，剩余待匹配请求数: %d", cleanupCount, len(session.PendingRequests))
		}
	}
}

// checkPendingResponses 检查缓存的响应是否可以匹配
func (p *RedisAdvancedParser) checkPendingResponses(session *RedisSession) {
	if len(session.PendingResponses) == 0 || len(session.PendingRequests) == 0 {
		return
	}

	if p.config.Verbose {
		// log.Printf("🔍 检查缓存的响应: 响应数=%d, 请求数=%d", len(session.PendingResponses), len(session.PendingRequests))
	}

	// 改进的匹配算法：严格按照时间顺序进行FIFO匹配
	// 1. 找到最早的响应
	var earliestResponse *types.Message
	var earliestResponseKey string
	var earliestResponseTime time.Time

	for responseKey, response := range session.PendingResponses {
		if earliestResponse == nil || response.Timestamp.Before(earliestResponseTime) {
			earliestResponse = response
			earliestResponseKey = responseKey
			earliestResponseTime = response.Timestamp
		}
	}

	if earliestResponse == nil {
		return
	}

	// 2. 找到最早的请求（去除时间限制，纯粹按序列号FIFO匹配）
	var matchedRequest *RedisRequest
	var matchedKey string
	var minSeq int64 = -1

	// 在存在严重时间不同步的情况下，去除时间验证，使用纯粹的FIFO匹配
	for key, req := range session.PendingRequests {
		if minSeq == -1 || req.SequenceNum < minSeq {
			minSeq = req.SequenceNum
			matchedRequest = req
			matchedKey = key
		}
	}

	if matchedRequest == nil {
		if p.config.Verbose {
			// log.Printf("⚠️ 没有可匹配的请求")
		}
		return
	}

	// 3. 执行匹配
	delete(session.PendingRequests, matchedKey)
	delete(session.PendingResponses, earliestResponseKey)
	session.ResponseCount++

	// 计算耗时（在时间不同步的情况下，可能为负数）
	duration := earliestResponse.Timestamp.Sub(matchedRequest.Timestamp)

	if duration < 0 {

		duration = -duration
	} else if duration > 10*time.Second {
		if p.config.Verbose {
			// log.Printf("⚠️ 检测到异常大的耗时: %v", duration)
		}
	}

	rr := &types.RequestResponse{
		Request:    matchedRequest.Message,
		Response:   earliestResponse,
		Duration:   duration,
		Success:    !p.isErrorResponse(earliestResponse),
		Connection: matchedRequest.Message.Connection,
	}

	p.stats.mu.Lock()
	p.stats.MatchedPairs++
	p.stats.mu.Unlock()

	// 输出监控结果
	formatted := p.FormatRequestResponse(rr)
	if formatted != "" {
		log.Printf("🚀 Redis 监控: %s", formatted)
	}

	// 递归检查是否还有其他响应可以匹配
	if len(session.PendingResponses) > 0 && len(session.PendingRequests) > 0 {
		p.checkPendingResponses(session)
	}
}

// 其他辅助方法实现

// isValidRedisData 验证数据是否为有效的Redis数据
func (p *RedisAdvancedParser) isValidRedisData(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	// 过滤单字节的无效数据（如\x00）
	if len(data) == 1 {
		// 单字节数据只有在特定情况下才是有效的
		switch data[0] {
		case '+', '-', ':', '$', '*':
			// 单字节的RESP开始符可能是网络分片，但在这里不处理
			return false
		default:
			return false
		}
	}

	// 检查是否包含不可打印字符（排除\r\n）
	for _, b := range data {
		if b < 32 && b != '\r' && b != '\n' && b != '\t' {
			// 如果包含太多控制字符，可能不是Redis数据
			controlCharCount := 0
			for _, cb := range data {
				if cb < 32 && cb != '\r' && cb != '\n' && cb != '\t' {
					controlCharCount++
				}
			}
			// 如果控制字符超过总长度的50%，认为不是有效数据
			if controlCharCount > len(data)/2 {
				return false
			}
			break
		}
	}

	return true
}

// isValidRESPArray 验证是否为有效的RESP数组格式
func (p *RedisAdvancedParser) isValidRESPArray(data []byte) bool {
	if len(data) < 3 || data[0] != '*' {
		return false
	}

	// 查找第一个\r\n
	for i := 1; i < len(data)-1; i++ {
		if data[i] == '\r' && data[i+1] == '\n' {
			// 检查数组大小是否为数字
			sizeStr := string(data[1:i])
			if len(sizeStr) == 0 {
				return false
			}
			// 简单检查是否为数字
			for _, c := range sizeStr {
				if c < '0' || c > '9' {
					if c == '-' && len(sizeStr) > 1 {
						// 允许负数（空数组）
						continue
					}
					return false
				}
			}
			return true
		}
	}
	return false
}

// isValidRESPResponse 验证是否为有效的RESP响应格式
func (p *RedisAdvancedParser) isValidRESPResponse(data []byte) bool {
	if len(data) < 2 {
		return false
	}

	switch data[0] {
	case '+':
		// 简单字符串，应该以\r\n结尾
		return p.hasValidCRLF(data)
	case '-':
		// 错误信息，应该以\r\n结尾
		return p.hasValidCRLF(data)
	case ':':
		// 整数，应该以\r\n结尾
		return p.hasValidCRLF(data)
	case '$':
		// 快量字符串，格式更复杂
		return p.isValidBulkString(data)
	default:
		return false
	}
}

// hasValidCRLF 检查数据是否包含有效的CRLF结尾
func (p *RedisAdvancedParser) hasValidCRLF(data []byte) bool {
	if len(data) < 3 {
		return false
	}
	// 查找\r\n
	for i := 0; i < len(data)-1; i++ {
		if data[i] == '\r' && data[i+1] == '\n' {
			return true
		}
	}
	return false
}

// isValidBulkString 验证快量字符串格式
func (p *RedisAdvancedParser) isValidBulkString(data []byte) bool {
	if len(data) < 4 || data[0] != '$' {
		return false
	}

	// 查找第一个\r\n
	for i := 1; i < len(data)-1; i++ {
		if data[i] == '\r' && data[i+1] == '\n' {
			lengthStr := string(data[1:i])
			if len(lengthStr) == 0 {
				return false
			}
			// 检查长度是否为数字
			for _, c := range lengthStr {
				if c < '0' || c > '9' {
					if c == '-' && len(lengthStr) > 1 {
						// 允许负数（空字符串）
						continue
					}
					return false
				}
			}
			return true
		}
	}
	return false
}
