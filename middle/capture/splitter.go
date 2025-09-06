// Package capture - 协议数据分割函数
package capture

import (
	"bytes"
)

// splitRedis Redis协议分割函数 (RESP协议)
func (s *tcpStream) splitRedis(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if len(data) == 0 {
		return 0, nil, nil
	}

	// Redis RESP协议分析
	switch data[0] {
	case '*': // 数组（多参数命令）
		return s.splitRespArray(data, atEOF)
	case '+', '-', ':': // 简单字符串、错误、整数
		return s.splitRespLine(data, atEOF)
	case '$': // 批量字符串
		return s.splitRespBulkString(data, atEOF)
	default:
		// 内联命令（非标准RESP）
		return s.splitRespLine(data, atEOF)
	}
}

// splitRespLine 分割以CRLF结尾的行
func (s *tcpStream) splitRespLine(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if idx := bytes.Index(data, []byte("\r\n")); idx != -1 {
		return idx + 2, data[:idx+2], nil
	}

	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}

	return 0, nil, nil
}

// splitRespBulkString 分割批量字符串 ($长度\r\n数据\r\n)
func (s *tcpStream) splitRespBulkString(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if len(data) < 3 { // 至少需要 $0\r\n
		return 0, nil, nil
	}

	// 查找第一个\r\n（长度行）
	if idx := bytes.Index(data[1:], []byte("\r\n")); idx != -1 {
		lengthEnd := idx + 1 + 2 // $之后的位置
		if lengthEnd <= len(data) {
			// 解析长度
			lengthStr := string(data[1 : lengthEnd-2])
			length := 0

			// 手动解析数字
			for _, r := range lengthStr {
				if r >= '0' && r <= '9' {
					length = length*10 + int(r-'0')
				} else if r == '-' && length == 0 {
					// 处理负数（空值）
					length = -1
					break
				}
			}

			if length == -1 {
				// 空值，只返回长度行
				return lengthEnd, data[:lengthEnd], nil
			}

			totalLen := lengthEnd + length + 2 // 长度头 + 数据 + \r\n
			if totalLen <= len(data) {
				return totalLen, data[:totalLen], nil
			}
		}
	}

	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}

	return 0, nil, nil
}

// splitRespArray 分割RESP数组 - 完整解析Redis命令
func (s *tcpStream) splitRespArray(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if len(data) < 4 { // 至少需要 *1\r\n
		return 0, nil, nil
	}

	// 解析数组长度
	if idx := bytes.Index(data[1:], []byte("\r\n")); idx != -1 {
		lengthEnd := idx + 1 + 2 // *之后的位置
		lengthStr := string(data[1 : lengthEnd-2])

		// 手动解析数组长度
		arrayLength := 0
		for _, r := range lengthStr {
			if r >= '0' && r <= '9' {
				arrayLength = arrayLength*10 + int(r-'0')
			}
		}

		if arrayLength <= 0 {
			return lengthEnd, data[:lengthEnd], nil
		}

		// 解析每个数组元素
		pos := lengthEnd
		for i := 0; i < arrayLength && pos < len(data); i++ {
			if pos >= len(data) {
				break
			}

			// 检查元素类型
			if data[pos] == '$' {
				// 批量字符串元素
				advance, _, _ := s.splitRespBulkString(data[pos:], false)
				if advance == 0 {
					// 数据不完整，等待更多数据
					if atEOF {
						return len(data), data, nil
					}
					return 0, nil, nil
				}
				pos += advance
			} else {
				// 其他类型，查找\r\n
				if lineIdx := bytes.Index(data[pos:], []byte("\r\n")); lineIdx != -1 {
					pos += lineIdx + 2
				} else {
					// 数据不完整
					if atEOF {
						return len(data), data, nil
					}
					return 0, nil, nil
				}
			}
		}

		// 所有元素都解析完成
		return pos, data[:pos], nil
	}

	// 如果在文件结尾且有数据，返回所有数据
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}

	return 0, nil, nil
}

// splitPostgres PostgreSQL协议分割函数
func (s *tcpStream) splitPostgres(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if len(data) < 5 {
		return 0, nil, nil
	}

	// PostgreSQL消息格式: 消息类型(1字节) + 长度(4字节) + 数据
	_ = data[0] // 消息类型，暂时不使用

	// 解析长度 (大端序)
	length := int(data[1])<<24 | int(data[2])<<16 | int(data[3])<<8 | int(data[4])

	// 长度包括长度字段本身(4字节)，但不包括消息类型字段
	totalLen := 1 + length

	if totalLen <= len(data) {
		return totalLen, data[:totalLen], nil
	}

	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}

	return 0, nil, nil
}

// splitSQLServer SQL Server TDS协议分割函数
func (s *tcpStream) splitSQLServer(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if len(data) < 8 {
		return 0, nil, nil
	}

	// TDS包头格式: 类型(1) + 状态(1) + 长度(2) + SPID(2) + 包ID(1) + 窗口(1)
	// 长度为大端序
	length := int(data[2])<<8 | int(data[3])

	if length <= len(data) {
		return length, data[:length], nil
	}

	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}

	return 0, nil, nil
}

// splitHTTP HTTP协议分割函数 (用于MinIO S3 API)
func (s *tcpStream) splitHTTP(data []byte, atEOF bool) (advance int, token []byte, err error) {
	// 查找HTTP消息结束
	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		if atEOF {
			return len(data), data, nil
		}
		return 0, nil, nil
	}

	// 检查是否有Content-Length
	header := data[:headerEnd]
	contentLengthPos := bytes.Index(bytes.ToLower(header), []byte("content-length:"))
	if contentLengthPos == -1 {
		// 没有body，只返回header
		return headerEnd + 4, data[:headerEnd+4], nil
	}

	// 解析Content-Length
	contentLengthStart := contentLengthPos + 15
	lineEnd := bytes.Index(header[contentLengthStart:], []byte("\r\n"))
	if lineEnd == -1 {
		return headerEnd + 4, data[:headerEnd+4], nil
	}

	contentLengthStr := string(bytes.TrimSpace(header[contentLengthStart : contentLengthStart+lineEnd]))
	contentLength := 0
	for _, r := range contentLengthStr {
		if r >= '0' && r <= '9' {
			contentLength = contentLength*10 + int(r-'0')
		}
	}

	totalLen := headerEnd + 4 + contentLength
	if totalLen <= len(data) {
		return totalLen, data[:totalLen], nil
	}

	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}

	return 0, nil, nil
}

// splitRocketMQ RocketMQ协议分割函数
func (s *tcpStream) splitRocketMQ(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if len(data) < 4 {
		return 0, nil, nil
	}

	// RocketMQ消息格式: 长度(4字节，大端序) + 数据
	length := int(data[0])<<24 | int(data[1])<<16 | int(data[2])<<8 | int(data[3])

	totalLen := 4 + length
	if totalLen <= len(data) {
		return totalLen, data[:totalLen], nil
	}

	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}

	return 0, nil, nil
}
