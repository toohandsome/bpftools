// Package parsers - Redis高级解析器的辅助方法和实现（续）
package parsers

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"github.com/myserver/go-server/ebpf/middle/types"
)

// parseRESPCommand 解析RESP格式的命令
func (p *RedisAdvancedParser) parseRESPCommand(data []byte) (*RedisParsedCommand, error) {
	if len(data) < 3 || data[0] != '*' {
		return nil, fmt.Errorf("无效的RESP数组格式")
	}

	// 解析数组长度
	lengthEnd := bytes.Index(data, []byte("\r\n"))
	if lengthEnd == -1 {
		return nil, fmt.Errorf("未找到数组长度结束符")
	}

	arrayLength, err := strconv.Atoi(string(data[1:lengthEnd]))
	if err != nil {
		return nil, fmt.Errorf("解析数组长度失败: %v", err)
	}

	if arrayLength <= 0 {
		return nil, fmt.Errorf("无效的数组长度: %d", arrayLength)
	}

	// 解析数组元素
	args := make([]string, 0, arrayLength)
	pos := lengthEnd + 2

	for i := 0; i < arrayLength && pos < len(data); i++ {
		if pos >= len(data) || data[pos] != '$' {
			break
		}

		// 查找元素长度结束符
		elemLengthEnd := bytes.Index(data[pos:], []byte("\r\n"))
		if elemLengthEnd == -1 {
			break
		}
		elemLengthEnd += pos

		// 解析元素长度
		elemLength, err := strconv.Atoi(string(data[pos+1 : elemLengthEnd]))
		if err != nil {
			break
		}

		// 提取元素数据
		elemDataStart := elemLengthEnd + 2
		if elemDataStart+elemLength > len(data) {
			break
		}

		element := string(data[elemDataStart : elemDataStart+elemLength])
		args = append(args, element)
		pos = elemDataStart + elemLength + 2 // 跳过数据和\r\n
	}

	if len(args) == 0 {
		return nil, fmt.Errorf("未能解析出命令参数")
	}

	return p.buildParsedCommand(args)
}

// parseInlineCommand 解析内联命令格式
func (p *RedisAdvancedParser) parseInlineCommand(data []byte) (*RedisParsedCommand, error) {
	line := string(bytes.TrimSpace(data))
	if line == "" {
		return nil, fmt.Errorf("空的内联命令")
	}

	// 简单分割参数
	args := strings.Fields(line)
	if len(args) == 0 {
		return nil, fmt.Errorf("无效的内联命令")
	}

	return p.buildParsedCommand(args)
}

// buildParsedCommand 构建解析后的命令
func (p *RedisAdvancedParser) buildParsedCommand(args []string) (*RedisParsedCommand, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("命令参数为空")
	}

	command := strings.ToUpper(args[0])
	parsedCmd := &RedisParsedCommand{
		Command: command,
		Args:    args,
	}

	// 获取命令元数据
	cmdMeta := p.commandTable.GetCommand(command)
	parsedCmd.CommandMeta = cmdMeta

	// 提取key和value
	if cmdMeta != nil && cmdMeta.FirstKey > 0 && len(args) > cmdMeta.FirstKey {
		parsedCmd.Key = args[cmdMeta.FirstKey]

		// 对于写命令，尝试提取value
		if cmdMeta.IsWrite && len(args) > cmdMeta.FirstKey+1 {
			switch command {
			case "SET", "SETNX", "SETEX", "PSETEX":
				if len(args) > 2 {
					parsedCmd.Value = args[2]
				}
			case "HSET":
				if len(args) > 3 {
					parsedCmd.Value = args[3]
				}
			case "LPUSH", "RPUSH", "SADD", "ZADD":
				if len(args) > 2 {
					// 对于多值命令，取第一个值
					parsedCmd.Value = args[2]
				}
			}
		}
	} else {
	// 对于没有key的特殊命令，尝试提取重要参数
		switch command {
		case "SELECT":
			// SELECT命令的数据库编号作为key
			if len(args) > 1 {
				parsedCmd.Key = args[1] // 数据库编号
				if p.config.Verbose {
					fmt.Printf("🔧 SELECT命令特殊处理: Key=%s\n", parsedCmd.Key)
				}
			}
		case "PING":
			// PING命令的可选参数
			if len(args) > 1 {
				parsedCmd.Value = args[1]
			}
		default:
			// 其他情况，如果有参数就使用第一个参数作为key
			if len(args) > 1 {
				parsedCmd.Key = args[1]
				if p.config.Verbose {
					fmt.Printf("🔧 默认处理: 命令=%s, Key=%s\n", command, parsedCmd.Key)
				}
			}
		}
	}

	return parsedCmd, nil
}

// parseRESPResponse 解析RESP格式的响应
func (p *RedisAdvancedParser) parseRESPResponse(data []byte) (*RedisParsedResponse, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("空响应数据")
	}

	respType := data[0]
	response := &RedisParsedResponse{
		Type: string(respType),
		Size: len(data),
	}

	switch respType {
	case '+': // 简单字符串
		content, err := p.parseSimpleString(data)
		if err != nil {
			return nil, err
		}
		response.Content = content

	case '-': // 错误
		content, err := p.parseError(data)
		if err != nil {
			return nil, err
		}
		response.Content = content
		response.IsError = true

	case ':': // 整数
		content, err := p.parseInteger(data)
		if err != nil {
			return nil, err
		}
		response.Content = content

	case '$': // 批量字符串
		content, err := p.parseBulkString(data)
		if err != nil {
			return nil, err
		}
		response.Content = content

	case '*': // 数组
		count, err := p.parseArrayCount(data)
		if err != nil {
			return nil, err
		}
		response.ElementCount = count
		response.Content = fmt.Sprintf("数组(%d个元素)", count)

	default:
		return nil, fmt.Errorf("未知的响应类型: %c", respType)
	}

	return response, nil
}

// 解析各种RESP类型的辅助方法

func (p *RedisAdvancedParser) parseSimpleString(data []byte) (string, error) {
	if len(data) < 3 || data[0] != '+' {
		return "", fmt.Errorf("无效的简单字符串格式")
	}

	end := bytes.Index(data, []byte("\r\n"))
	if end == -1 {
		return string(data[1:]), nil
	}
	return string(data[1:end]), nil
}

func (p *RedisAdvancedParser) parseError(data []byte) (string, error) {
	if len(data) < 3 || data[0] != '-' {
		return "", fmt.Errorf("无效的错误格式")
	}

	end := bytes.Index(data, []byte("\r\n"))
	if end == -1 {
		return string(data[1:]), nil
	}
	return string(data[1:end]), nil
}

func (p *RedisAdvancedParser) parseInteger(data []byte) (string, error) {
	if len(data) < 3 || data[0] != ':' {
		return "", fmt.Errorf("无效的整数格式")
	}

	end := bytes.Index(data, []byte("\r\n"))
	if end == -1 {
		return string(data[1:]), nil
	}
	return string(data[1:end]), nil
}

func (p *RedisAdvancedParser) parseBulkString(data []byte) (string, error) {
	if len(data) < 3 || data[0] != '$' {
		return "", fmt.Errorf("无效的批量字符串格式")
	}

	lengthEnd := bytes.Index(data, []byte("\r\n"))
	if lengthEnd == -1 {
		return "", fmt.Errorf("未找到长度结束符")
	}

	length, err := strconv.Atoi(string(data[1:lengthEnd]))
	if err != nil {
		return "", fmt.Errorf("解析长度失败: %v", err)
	}

	if length == -1 {
		return "(nil)", nil
	}

	if length == 0 {
		return "", nil
	}

	dataStart := lengthEnd + 2
	if dataStart+length > len(data) {
		return "", fmt.Errorf("数据不完整")
	}

	return string(data[dataStart : dataStart+length]), nil
}

func (p *RedisAdvancedParser) parseArrayCount(data []byte) (int, error) {
	if len(data) < 3 || data[0] != '*' {
		return 0, fmt.Errorf("无效的数组格式")
	}

	end := bytes.Index(data, []byte("\r\n"))
	if end == -1 {
		return 0, fmt.Errorf("未找到数组长度结束符")
	}

	count, err := strconv.Atoi(string(data[1:end]))
	if err != nil {
		return 0, fmt.Errorf("解析数组长度失败: %v", err)
	}

	return count, nil
}

// 判断和辅助方法

func (p *RedisAdvancedParser) isInlineCommand(data []byte) bool {
	line := string(bytes.TrimSpace(data))
	upper := strings.ToUpper(line)
	
	// 检查常见的Redis命令
	commands := []string{"PING", "GET", "SET", "INFO", "KEYS", "SELECT"}
	for _, cmd := range commands {
		if strings.HasPrefix(upper, cmd) {
			return true
		}
	}
	return false
}

func (p *RedisAdvancedParser) isArrayResponse(data []byte) bool {
	// 简单启发式：如果数组长度很大，可能是响应
	if len(data) < 3 || data[0] != '*' {
		return false
	}

	end := bytes.Index(data, []byte("\r\n"))
	if end == -1 {
		return false
	}

	count, err := strconv.Atoi(string(data[1:end]))
	if err != nil {
		return false
	}

	// 如果数组元素很多，更可能是响应（如SCAN、KEYS命令的响应）
	return count > 10
}

func (p *RedisAdvancedParser) isErrorResponse(msg *types.Message) bool {
	if respData, ok := msg.ParsedData.(*RedisParsedResponse); ok {
		return respData.IsError
	}
	return len(msg.Data) > 0 && msg.Data[0] == '-'
}

func (p *RedisAdvancedParser) getResponseType(firstByte byte) string {
	switch firstByte {
	case '+':
		return "SimpleString"
	case '-':
		return "Error"
	case ':':
		return "Integer"
	case '$':
		return "BulkString"
	case '*':
		return "Array"
	default:
		return "Unknown"
	}
}

// formatRequestBody 格式化请求体
func (p *RedisAdvancedParser) formatRequestBody(parsedCmd *RedisParsedCommand) string {
	if parsedCmd.Value != "" {
		return p.truncateString(parsedCmd.Value, p.config.MaxContentLength)
	}
	
	// 对于没有明确value的命令，显示key或第一个参数
	if parsedCmd.Key != "" {
		return p.truncateString(parsedCmd.Key, p.config.MaxContentLength)
	}
	
	if len(parsedCmd.Args) > 1 {
		return p.truncateString(parsedCmd.Args[1], p.config.MaxContentLength)
	}
	
	return "-"
}

func (p *RedisAdvancedParser) formatResponseBody(parsedResp *RedisParsedResponse) string {
	if parsedResp.IsError {
		return p.truncateString(parsedResp.Content, p.config.MaxContentLength)
	}
	
	if parsedResp.Type == "*" {
		return fmt.Sprintf("array(%d)", parsedResp.ElementCount)
	}
	
	content := parsedResp.Content
	if content == "" {
		content = "OK"
	}
	
	return p.truncateString(content, p.config.MaxContentLength)
}

func (p *RedisAdvancedParser) getClientInfo(conn *types.Connection) (ip, port string) {
	ip, port = "-", "-"
	
	if conn == nil {
		return
	}
	
	// 根据方向判断客户端地址
	var clientAddr string
	if conn.Direction == types.DirectionOutbound {
		clientAddr = conn.LocalAddr
	} else {
		clientAddr = conn.RemoteAddr
	}
	
	// 解析地址
	parts := strings.Split(clientAddr, ":")
	if len(parts) == 2 {
		ip = parts[0]
		port = parts[1]
	}
	
	return
}

func (p *RedisAdvancedParser) truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}