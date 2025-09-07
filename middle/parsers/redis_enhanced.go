// Package parsers - 增强的Redis协议解析器（已弃用，请使用RedisAdvancedParser）
// 此文件保留用于向后兼容，建议使用redis_advanced.go中的新实现
package parsers

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/myserver/go-server/ebpf/middle/types"
)

// RedisEnhancedParser 增强的Redis解析器，支持请求响应关联
type RedisEnhancedParser struct {
	// 请求响应匹配器
	matcher *RequestResponseMatcher

	// Redis数据库跟踪器
	dbTracker *RedisDatabaseTracker

	// 解析器配置
	config *RedisParserConfig
}

// RedisParserConfig Redis解析器配置
type RedisParserConfig struct {
	MaxContentLength int  // 最大内容长度
	EnableDBTracking bool // 是否启用数据库跟踪
	Verbose          bool // 是否详细日志
}

// RequestResponseMatcher 请求响应匹配器
type RequestResponseMatcher struct {
	pendingRequests map[string]*PendingRequest // 待匹配的请求
	mu              sync.RWMutex
	maxPendingTime  time.Duration // 最大等待时间
}

// PendingRequest 待匹配的请求
type PendingRequest struct {
	Message   *types.Message
	Timestamp time.Time
	ConnKey   string
}

// RedisDatabaseTracker Redis数据库跟踪器
type RedisDatabaseTracker struct {
	currentDBs map[string]string // 连接 -> 当前数据库
	mu         sync.RWMutex
}

// NewRedisEnhancedParser 创建增强的Redis解析器
func NewRedisEnhancedParser(config *RedisParserConfig) *RedisEnhancedParser {
	if config == nil {
		config = &RedisParserConfig{
			MaxContentLength: 64,
			EnableDBTracking: true,
			Verbose:          false,
		}
	}

	return &RedisEnhancedParser{
		matcher: &RequestResponseMatcher{
			pendingRequests: make(map[string]*PendingRequest),
			maxPendingTime:  30 * time.Second, // 30秒超时
		},
		dbTracker: &RedisDatabaseTracker{
			currentDBs: make(map[string]string),
		},
		config: config,
	}
}

// GetProtocol 获取协议名称
func (p *RedisEnhancedParser) GetProtocol() string {
	return "redis"
}

// GetDefaultPort 获取默认端口
func (p *RedisEnhancedParser) GetDefaultPort() int {
	return 6379
}

// IsRequest 判断是否为请求
func (p *RedisEnhancedParser) IsRequest(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	// Redis请求通常以*开头(数组)
	switch data[0] {
	case '*':
		return true
	case '+', '-', ':', '$':
		return false
	default:
		// 简单的内联命令检测
		line := string(bytes.TrimSpace(data))
		upper := strings.ToUpper(line)
		return strings.Contains(upper, "PING") ||
			strings.Contains(upper, "GET") ||
			strings.Contains(upper, "SET") ||
			strings.Contains(upper, "INFO")
	}
}

// IsResponse 判断是否为响应
func (p *RedisEnhancedParser) IsResponse(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	// Redis响应的标识符
	switch data[0] {
	case '+', '-', ':', '$':
		return true
	case '*':
		return false // 数组通常是请求
	default:
		return false
	}
}

// ParseRequest 解析请求
func (p *RedisEnhancedParser) ParseRequest(data []byte) (*types.Message, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("空数据")
	}

	msg := &types.Message{
		Type:      "request",
		Data:      data,
		Size:      len(data),
		Timestamp: time.Now(),
	}

	var err error

	if data[0] == '*' {
		// 解析RESP数组格式的命令
		msg.ParsedData, err = p.parseRESPArray(data)
		if err != nil {
			return nil, fmt.Errorf("解析RESP数组失败: %v", err)
		}

		// 提取命令名和生成ID
		if arr, ok := msg.ParsedData.([]string); ok && len(arr) > 0 {
			msg.Command = strings.ToUpper(arr[0])
			msg.ID = p.generateRequestID(msg)

			// 处理SELECT命令
			if p.config.EnableDBTracking && strings.ToUpper(arr[0]) == "SELECT" && len(arr) > 1 {
				p.handleSelectCommand(msg.Connection, arr[1])
			}
		}
	} else {
		// 解析内联命令
		line := string(bytes.TrimSpace(data))
		parts := strings.Fields(line)
		if len(parts) > 0 {
			msg.Command = strings.ToUpper(parts[0])
			msg.ParsedData = parts
			msg.ID = p.generateRequestID(msg)
		}
	}

	// 注册待匹配的请求
	p.registerPendingRequest(msg)

	return msg, nil
}

// ParseResponse 解析响应
func (p *RedisEnhancedParser) ParseResponse(data []byte) (*types.Message, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("空数据")
	}

	msg := &types.Message{
		Type:      "response",
		Data:      data,
		Size:      len(data),
		Timestamp: time.Now(),
	}

	var err error

	switch data[0] {
	case '+': // 简单字符串
		msg.ParsedData, err = p.parseSimpleString(data)
		msg.Command = "SimpleString"
	case '-': // 错误响应
		msg.ParsedData, err = p.parseError(data)
		msg.Command = "Error"
	case ':': // 整数
		msg.ParsedData, err = p.parseInteger(data)
		msg.Command = "Integer"
	case '$': // 批量字符串
		msg.ParsedData, err = p.parseBulkString(data)
		msg.Command = "BulkString"
	case '*': // 数组
		msg.ParsedData, err = p.parseRESPArray(data)
		msg.Command = "Array"
	default:
		msg.ParsedData = string(data)
		msg.Command = "Unknown"
	}

	if err != nil {
		return nil, fmt.Errorf("解析响应失败: %v", err)
	}

	return msg, nil
}

// MatchRequestResponse 匹配请求和响应
func (p *RedisEnhancedParser) MatchRequestResponse(response *types.Message) *types.RequestResponse {
	// 尝试匹配最近的请求
	request := p.findMatchingRequest(response)
	if request == nil {
		return nil
	}

	// 创建请求响应对
	rr := &types.RequestResponse{
		Request:    request,
		Response:   response,
		Duration:   response.Timestamp.Sub(request.Timestamp),
		Success:    !p.isErrorResponse(response),
		Connection: request.Connection,
	}

	if !rr.Success {
		if errorMsg, ok := response.ParsedData.(string); ok {
			rr.ErrorMsg = errorMsg
		}
	}

	return rr
}

// FormatRequestResponse 格式化请求响应对输出
func (p *RedisEnhancedParser) FormatRequestResponse(rr *types.RequestResponse) string {
	if rr == nil {
		return ""
	}

	// 获取数据库信息
	db := p.getCurrentDatabase(rr.Connection)

	// 解析请求内容
	cmd, key, reqBody := p.extractRequestInfo(rr.Request)

	// 解析响应内容
	respBody := p.extractResponseInfo(rr.Response)

	// 计算耗时
	duration := rr.Duration.Microseconds()

	// 格式化输出
	return fmt.Sprintf("db=%s cmd=%s key=%s req=%s resp=%s cost=%dμs",
		db, cmd, key, reqBody, respBody, duration)
}

// 内部方法实现

// parseRESPArray 解析RESP数组
func (p *RedisEnhancedParser) parseRESPArray(data []byte) ([]string, error) {
	if len(data) < 3 || data[0] != '*' {
		return nil, fmt.Errorf("无效的数组格式")
	}

	// 查找第一个\r\n
	lengthEnd := bytes.Index(data, []byte("\r\n"))
	if lengthEnd == -1 {
		return nil, fmt.Errorf("未找到数组长度结束符")
	}

	// 解析数组长度
	lengthStr := string(data[1:lengthEnd])
	arrayLength, err := strconv.Atoi(lengthStr)
	if err != nil {
		return nil, fmt.Errorf("解析数组长度失败: %v", err)
	}

	if arrayLength == -1 {
		return nil, nil // null array
	}

	result := make([]string, 0, arrayLength)
	pos := lengthEnd + 2

	for i := 0; i < arrayLength && pos < len(data); i++ {
		if pos >= len(data) {
			break
		}

		if data[pos] == '$' {
			// 解析批量字符串
			elemLengthEnd := bytes.Index(data[pos:], []byte("\r\n"))
			if elemLengthEnd == -1 {
				break
			}
			elemLengthEnd += pos

			elemLengthStr := string(data[pos+1 : elemLengthEnd])
			elemLength, err := strconv.Atoi(elemLengthStr)
			if err != nil {
				break
			}

			elemDataStart := elemLengthEnd + 2
			if elemDataStart+elemLength > len(data) {
				break
			}

			result = append(result, string(data[elemDataStart:elemDataStart+elemLength]))
			pos = elemDataStart + elemLength + 2
		} else {
			// 其他类型
			lineEnd := bytes.Index(data[pos:], []byte("\r\n"))
			if lineEnd == -1 {
				break
			}
			lineEnd += pos
			result = append(result, string(data[pos:lineEnd]))
			pos = lineEnd + 2
		}
	}

	return result, nil
}

// parseSimpleString 解析简单字符串
func (p *RedisEnhancedParser) parseSimpleString(data []byte) (string, error) {
	if len(data) < 3 || data[0] != '+' {
		return "", fmt.Errorf("无效的简单字符串格式")
	}

	end := bytes.Index(data, []byte("\r\n"))
	if end == -1 {
		return string(data[1:]), nil
	}

	return string(data[1:end]), nil
}

// parseError 解析错误响应
func (p *RedisEnhancedParser) parseError(data []byte) (string, error) {
	if len(data) < 3 || data[0] != '-' {
		return "", fmt.Errorf("无效的错误格式")
	}

	end := bytes.Index(data, []byte("\r\n"))
	if end == -1 {
		return string(data[1:]), nil
	}

	return string(data[1:end]), nil
}

// parseInteger 解析整数
func (p *RedisEnhancedParser) parseInteger(data []byte) (int64, error) {
	if len(data) < 3 || data[0] != ':' {
		return 0, fmt.Errorf("无效的整数格式")
	}

	end := bytes.Index(data, []byte("\r\n"))
	if end == -1 {
		end = len(data)
	}

	return strconv.ParseInt(string(data[1:end]), 10, 64)
}

// parseBulkString 解析批量字符串
func (p *RedisEnhancedParser) parseBulkString(data []byte) (string, error) {
	if len(data) < 3 || data[0] != '$' {
		return "", fmt.Errorf("无效的批量字符串格式")
	}

	lengthEnd := bytes.Index(data, []byte("\r\n"))
	if lengthEnd == -1 {
		return "", fmt.Errorf("未找到长度结束符")
	}

	lengthStr := string(data[1:lengthEnd])
	length, err := strconv.Atoi(lengthStr)
	if err != nil {
		return "", fmt.Errorf("解析长度失败: %v", err)
	}

	if length == -1 {
		return "", nil // null bulk string
	}

	dataStart := lengthEnd + 2
	if dataStart+length > len(data) {
		return "", fmt.Errorf("数据不完整")
	}

	return string(data[dataStart : dataStart+length]), nil
}

// generateRequestID 生成请求ID
func (p *RedisEnhancedParser) generateRequestID(msg *types.Message) string {
	connKey := p.getConnectionKey(msg.Connection)
	timestamp := msg.Timestamp.UnixNano()
	return fmt.Sprintf("%s_%d", connKey, timestamp)
}

// getConnectionKey 获取连接唯一标识
func (p *RedisEnhancedParser) getConnectionKey(conn *types.Connection) string {
	if conn == nil {
		return "unknown"
	}
	return fmt.Sprintf("%s->%s", conn.LocalAddr, conn.RemoteAddr)
}

// getNormalizedConnectionKey 获取标准化的连接键（不考虑方向）
func (p *RedisEnhancedParser) getNormalizedConnectionKey(conn *types.Connection) string {
	if conn == nil {
		return "unknown"
	}
	// 对地址进行排序，确保相同连接的请求和响应使用相同的键
	addr1, addr2 := conn.LocalAddr, conn.RemoteAddr
	if addr1 > addr2 {
		addr1, addr2 = addr2, addr1
	}
	return fmt.Sprintf("%s<->%s", addr1, addr2)
}

// registerPendingRequest 注册待匹配的请求
func (p *RedisEnhancedParser) registerPendingRequest(msg *types.Message) {
	// 使用标准化的连接键（不考虑方向）
	connKey := p.getNormalizedConnectionKey(msg.Connection)

	p.matcher.mu.Lock()
	defer p.matcher.mu.Unlock()

	// 清理过期的请求
	p.cleanExpiredRequests()

	// 注册新请求
	p.matcher.pendingRequests[connKey] = &PendingRequest{
		Message:   msg,
		Timestamp: msg.Timestamp,
		ConnKey:   connKey,
	}
}

// findMatchingRequest 查找匹配的请求
func (p *RedisEnhancedParser) findMatchingRequest(response *types.Message) *types.Message {
	// 使用标准化的连接键（不考虑方向）
	connKey := p.getNormalizedConnectionKey(response.Connection)

	p.matcher.mu.Lock()
	defer p.matcher.mu.Unlock()

	// 查找对应的请求
	if pending, exists := p.matcher.pendingRequests[connKey]; exists {
		delete(p.matcher.pendingRequests, connKey)
		return pending.Message
	}

	return nil
}

// cleanExpiredRequests 清理过期的请求
func (p *RedisEnhancedParser) cleanExpiredRequests() {
	now := time.Now()
	for key, pending := range p.matcher.pendingRequests {
		if now.Sub(pending.Timestamp) > p.matcher.maxPendingTime {
			delete(p.matcher.pendingRequests, key)
		}
	}
}

// isErrorResponse 判断是否为错误响应
func (p *RedisEnhancedParser) isErrorResponse(msg *types.Message) bool {
	return len(msg.Data) > 0 && msg.Data[0] == '-'
}

// handleSelectCommand 处理SELECT命令
func (p *RedisEnhancedParser) handleSelectCommand(conn *types.Connection, db string) {
	connKey := p.getConnectionKey(conn)

	p.dbTracker.mu.Lock()
	p.dbTracker.currentDBs[connKey] = db
	p.dbTracker.mu.Unlock()
}

// getCurrentDatabase 获取当前数据库
func (p *RedisEnhancedParser) getCurrentDatabase(conn *types.Connection) string {
	connKey := p.getConnectionKey(conn)

	p.dbTracker.mu.RLock()
	db, exists := p.dbTracker.currentDBs[connKey]
	p.dbTracker.mu.RUnlock()

	if !exists {
		return "0" // 默认数据库
	}
	return db
}

// extractRequestInfo 提取请求信息
func (p *RedisEnhancedParser) extractRequestInfo(msg *types.Message) (cmd, key, body string) {
	cmd = strings.ToLower(msg.Command)
	key = "-"
	body = "-"

	if msg.ParsedData != nil {
		if args, ok := msg.ParsedData.([]string); ok && len(args) > 0 {
			cmd = strings.ToLower(args[0])

			// 提取key
			if len(args) > 1 {
				key = p.truncateString(args[1], 16)
			}

			// 提取value (针对SET命令)
			if len(args) > 2 && strings.ToUpper(args[0]) == "SET" {
				body = p.truncateString(args[2], p.config.MaxContentLength)
			} else if len(args) > 1 {
				// 对于其他命令，显示第一个参数
				body = p.truncateString(args[1], p.config.MaxContentLength)
			}
		}
	}

	return cmd, key, body
}

// extractResponseInfo 提取响应信息
func (p *RedisEnhancedParser) extractResponseInfo(msg *types.Message) string {
	if msg.ParsedData != nil {
		if respData, ok := msg.ParsedData.(string); ok {
			return p.truncateString(respData, p.config.MaxContentLength)
		}
		if respData, ok := msg.ParsedData.(int64); ok {
			return fmt.Sprintf("%d", respData)
		}
	}
	return "-"
}

// GetConnectionKey 获取连接唯一标识（公开方法）
func (p *RedisEnhancedParser) GetConnectionKey(conn *types.Connection) string {
	return p.getConnectionKey(conn)
}

// truncateString 截断字符串
func (p *RedisEnhancedParser) truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
