// Package parsers - Redis协议解析器 (RESP协议)
package parsers

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/myserver/go-server/ebpf/middle/types"
)

// RedisParser Redis协议解析器
type RedisParser struct{}

// NewRedisParser 创建Redis解析器
func NewRedisParser() *RedisParser {
	return &RedisParser{}
}

// GetProtocol 获取协议名称
func (p *RedisParser) GetProtocol() string {
	return "redis"
}

// GetDefaultPort 获取默认端口
func (p *RedisParser) GetDefaultPort() int {
	return 6379
}

// 判断是否为请求
func (p *RedisParser) IsRequest(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	// Redis请求通常以*开头(数组)，或者是简单命令
	switch data[0] {
	case '*': // 多个参数的命令 (如: *3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n)
		return true
	case '+', '-', ':', '$': // 这些通常是响应
		return false
	default:
		// 简单的内联命令 (如: PING\r\n)
		line := string(bytes.TrimSpace(data))
		upper := strings.ToUpper(line)
		if strings.Contains(upper, "PING") ||
			strings.Contains(upper, "GET") ||
			strings.Contains(upper, "SET") ||
			strings.Contains(upper, "INFO") {
			return true
		}
		return false
	}
}

// IsResponse 判断是否为响应
func (p *RedisParser) IsResponse(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	// Redis响应的第一个字符标识响应类型
	switch data[0] {
	case '+': // 简单字符串 (如: +OK\r\n)
		return true
	case '-': // 错误 (如: -ERR unknown command\r\n)
		return true
	case ':': // 整数 (如: :100\r\n)
		return true
	case '$': // 批量字符串 (如: $5\r\nhello\r\n)
		return true
	case '*': // 数组，通常是命令请求，很少作为响应
		// 在Redis中，*开头的数组几乎总是请求（命令），不是响应
		return false
	default:
		return false
	}
}

// ParseRequest 解析请求
func (p *RedisParser) ParseRequest(data []byte) (*types.Message, error) {
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

		// 提取命令名
		if arr, ok := msg.ParsedData.([]string); ok && len(arr) > 0 {
			msg.Command = strings.ToUpper(arr[0])
			msg.ID = p.generateRequestID(arr)
		}
	} else {
		// 解析内联命令
		line := string(bytes.TrimSpace(data))
		parts := strings.Fields(line)
		if len(parts) > 0 {
			msg.Command = strings.ToUpper(parts[0])
			msg.ParsedData = parts
			msg.ID = p.generateRequestID(parts)
		}
	}

	return msg, nil
}

// ParseResponse 解析响应
func (p *RedisParser) ParseResponse(data []byte) (*types.Message, error) {
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

	// 生成响应ID（简单的哈希）
	msg.ID = p.generateResponseID(data)

	return msg, nil
}

// parseSimpleString 解析简单字符串 (+OK\r\n)
func (p *RedisParser) parseSimpleString(data []byte) (string, error) {
	if len(data) < 3 || data[0] != '+' {
		return "", fmt.Errorf("无效的简单字符串格式")
	}

	end := bytes.Index(data, []byte("\r\n"))
	if end == -1 {
		return string(data[1:]), nil
	}

	return string(data[1:end]), nil
}

// parseError 解析错误响应 (-ERR message\r\n)
func (p *RedisParser) parseError(data []byte) (string, error) {
	if len(data) < 3 || data[0] != '-' {
		return "", fmt.Errorf("无效的错误格式")
	}

	end := bytes.Index(data, []byte("\r\n"))
	if end == -1 {
		return string(data[1:]), nil
	}

	return string(data[1:end]), nil
}

// parseInteger 解析整数 (:100\r\n)
func (p *RedisParser) parseInteger(data []byte) (int64, error) {
	if len(data) < 3 || data[0] != ':' {
		return 0, fmt.Errorf("无效的整数格式")
	}

	end := bytes.Index(data, []byte("\r\n"))
	if end == -1 {
		end = len(data)
	} else {
		end = end
	}

	return strconv.ParseInt(string(data[1:end]), 10, 64)
}

// parseBulkString 解析批量字符串 ($5\r\nhello\r\n)
func (p *RedisParser) parseBulkString(data []byte) (string, error) {
	if len(data) < 3 || data[0] != '$' {
		return "", fmt.Errorf("无效的批量字符串格式")
	}

	// 查找第一个\r\n
	lengthEnd := bytes.Index(data, []byte("\r\n"))
	if lengthEnd == -1 {
		return "", fmt.Errorf("未找到长度结束符")
	}

	// 解析长度
	lengthStr := string(data[1:lengthEnd])
	length, err := strconv.Atoi(lengthStr)
	if err != nil {
		return "", fmt.Errorf("解析长度失败: %v", err)
	}

	if length == -1 {
		return "", nil // null bulk string
	}

	// 提取数据
	dataStart := lengthEnd + 2
	if dataStart+length > len(data) {
		return "", fmt.Errorf("数据不完整")
	}

	return string(data[dataStart : dataStart+length]), nil
}

// parseRESPArray 解析RESP数组 (*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n)
func (p *RedisParser) parseRESPArray(data []byte) ([]string, error) {
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

		// 解析每个元素（假设都是批量字符串）
		if data[pos] == '$' {
			// 查找长度结束符
			elemLengthEnd := bytes.Index(data[pos:], []byte("\r\n"))
			if elemLengthEnd == -1 {
				break
			}
			elemLengthEnd += pos

			// 解析元素长度
			elemLengthStr := string(data[pos+1 : elemLengthEnd])
			elemLength, err := strconv.Atoi(elemLengthStr)
			if err != nil {
				break
			}

			// 提取元素数据
			elemDataStart := elemLengthEnd + 2
			if elemDataStart+elemLength > len(data) {
				break
			}

			result = append(result, string(data[elemDataStart:elemDataStart+elemLength]))
			pos = elemDataStart + elemLength + 2 // 跳过数据和\r\n
		} else {
			// 其他类型，简单处理
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

// generateRequestID 生成请求ID
func (p *RedisParser) generateRequestID(args []string) string {
	if len(args) == 0 {
		return fmt.Sprintf("req_%d", time.Now().UnixNano())
	}

	// 使用时间戳确保唯一性
	timestamp := time.Now().UnixNano()

	// 简单的ID生成策略：命令+参数+时间戳
	id := strings.ToUpper(args[0])
	if len(args) > 1 {
		// 对于有key的命令，加上key
		switch strings.ToUpper(args[0]) {
		case "GET", "SET", "DEL", "EXISTS", "INCR", "DECR":
			if len(args) > 1 {
				id += ":" + args[1]
			}
		}
	}
	return fmt.Sprintf("%s_%d", id, timestamp)
}

// generateResponseID 生成响应ID（与请求匹配）
func (p *RedisParser) generateResponseID(data []byte) string {
	// 对于响应，我们需要根据连接信息来匹配
	// 这里暂时使用简单的时间戳，后续在stream层面进行匹配
	return fmt.Sprintf("resp_%d", time.Now().UnixNano())
}
