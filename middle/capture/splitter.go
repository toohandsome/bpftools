// Package capture - 协议数据分割函数
package capture

import (
	"bytes"
)

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
