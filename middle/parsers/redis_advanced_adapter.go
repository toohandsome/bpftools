// Package parsers - Redis高级解析器适配器
package parsers

import (
	"github.com/myserver/go-server/ebpf/middle/types"
)

// RedisAdvancedParserAdapter 高级Redis解析器适配器，实现标准ProtocolParser接口
type RedisAdvancedParserAdapter struct {
	parser *RedisAdvancedParser
}

// NewRedisAdvancedParserAdapter 创建高级Redis解析器适配器
func NewRedisAdvancedParserAdapter(config *RedisAdvancedConfig) *RedisAdvancedParserAdapter {
	return &RedisAdvancedParserAdapter{
		parser: NewRedisAdvancedParser(config),
	}
}

// ParseRequest 解析请求（适配器方法）
func (a *RedisAdvancedParserAdapter) ParseRequest(data []byte) (*types.Message, error) {
	return a.parser.ParseRequest(data)
}

// ParseResponse 解析响应（适配器方法）
func (a *RedisAdvancedParserAdapter) ParseResponse(data []byte) (*types.Message, error) {
	return a.parser.ParseResponse(data)
}

// IsRequest 判断是否为请求（适配器方法）
func (a *RedisAdvancedParserAdapter) IsRequest(data []byte) bool {
	return a.parser.IsRequest(data)
}

// IsResponse 判断是否为响应（适配器方法）
func (a *RedisAdvancedParserAdapter) IsResponse(data []byte) bool {
	return a.parser.IsResponse(data)
}

// GetProtocol 获取协议名称（适配器方法）
func (a *RedisAdvancedParserAdapter) GetProtocol() string {
	return a.parser.GetProtocol()
}

// GetDefaultPort 获取默认端口（适配器方法）
func (a *RedisAdvancedParserAdapter) GetDefaultPort() int {
	return a.parser.GetDefaultPort()
}

// MatchRequestResponse 匹配请求和响应（扩展方法）
func (a *RedisAdvancedParserAdapter) MatchRequestResponse(response *types.Message) *types.RequestResponse {
	return a.parser.MatchRequestResponse(response)
}

// FormatRequestResponse 格式化请求响应对（扩展方法）
func (a *RedisAdvancedParserAdapter) FormatRequestResponse(rr *types.RequestResponse) string {
	return a.parser.FormatRequestResponse(rr)
}

// GetParser 获取内部解析器（扩展方法）
func (a *RedisAdvancedParserAdapter) GetParser() *RedisAdvancedParser {
	return a.parser
}

// RegisterRequestManually 手动注册请求（扩展方法）
func (a *RedisAdvancedParserAdapter) RegisterRequestManually(msg *types.Message, parsedCmd *RedisParsedCommand) {
	a.parser.RegisterRequestManually(msg, parsedCmd)
}
