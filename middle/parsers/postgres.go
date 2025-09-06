// Package parsers - PostgreSQL协议解析器 (Wire Protocol)
package parsers

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/myserver/go-server/ebpf/middle/types"
)

// PostgresParser PostgreSQL协议解析器
type PostgresParser struct{}

// NewPostgresParser 创建PostgreSQL解析器
func NewPostgresParser() *PostgresParser {
	return &PostgresParser{}
}

// GetProtocol 获取协议名称
func (p *PostgresParser) GetProtocol() string {
	return "postgres"
}

// GetDefaultPort 获取默认端口
func (p *PostgresParser) GetDefaultPort() int {
	return 5432
}

// IsRequest 判断是否为请求
func (p *PostgresParser) IsRequest(data []byte) bool {
	if len(data) < 5 {
		return false
	}

	msgType := data[0]

	// 客户端请求消息类型
	switch msgType {
	case 'Q': // Query (简单查询)
		return true
	case 'P': // Parse (预处理语句)
		return true
	case 'B': // Bind (绑定参数)
		return true
	case 'E': // Execute (执行)
		return true
	case 'D': // Describe (描述)
		return true
	case 'H': // Flush
		return true
	case 'S': // Sync
		return true
	case 'C': // Close
		return true
	case 'X': // Terminate
		return true
	case 'p': // Password message
		return true
	case 'F': // Function call
		return true
	default:
		// 启动消息没有消息类型字节，直接是长度
		if msgType == 0x00 && len(data) >= 8 {
			// 检查是否是启动消息（长度后面跟协议版本）
			length := binary.BigEndian.Uint32(data[0:4])
			if length >= 8 && int(length) <= len(data) {
				return true
			}
		}
		return false
	}
}

// IsResponse 判断是否为响应
func (p *PostgresParser) IsResponse(data []byte) bool {
	if len(data) < 5 {
		return false
	}

	msgType := data[0]

	// 服务端响应消息类型
	switch msgType {
	case 'R': // Authentication
		return true
	case 'K': // BackendKeyData
		return true
	case 'S': // ParameterStatus
		return true
	case 'Z': // ReadyForQuery
		return true
	case 'T': // RowDescription
		return true
	case 'D': // DataRow
		return true
	case 'C': // CommandComplete
		return true
	case 'E': // ErrorResponse
		return true
	case 'N': // NoticeResponse
		return true
	case '1': // ParseComplete
		return true
	case '2': // BindComplete
		return true
	case '3': // CloseComplete
		return true
	case 'n': // NoData
		return true
	case 's': // PortalSuspended
		return true
	case 'I': // EmptyQueryResponse
		return true
	case 'V': // FunctionCallResponse
		return true
	default:
		return false
	}
}

// ParseRequest 解析请求
func (p *PostgresParser) ParseRequest(data []byte) (*types.Message, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("数据包太短")
	}

	msg := &types.Message{
		Type:      "request",
		Data:      data,
		Size:      len(data),
		Timestamp: time.Now(),
	}

	msgType := data[0]
	length := binary.BigEndian.Uint32(data[1:5])

	var parsedData PostgresMessage
	var err error

	switch msgType {
	case 'Q': // Query
		parsedData, err = p.parseQuery(data[5 : length+1])
		msg.Command = "Query"
	case 'P': // Parse
		parsedData, err = p.parseParse(data[5 : length+1])
		msg.Command = "Parse"
	case 'B': // Bind
		parsedData, err = p.parseBind(data[5 : length+1])
		msg.Command = "Bind"
	case 'E': // Execute
		parsedData, err = p.parseExecute(data[5 : length+1])
		msg.Command = "Execute"
	case 'D': // Describe
		parsedData, err = p.parseDescribe(data[5 : length+1])
		msg.Command = "Describe"
	case 'C': // Close
		parsedData, err = p.parseClose(data[5 : length+1])
		msg.Command = "Close"
	case 'X': // Terminate
		parsedData = PostgresMessage{Type: "Terminate"}
		msg.Command = "Terminate"
	case 'S': // Sync
		parsedData = PostgresMessage{Type: "Sync"}
		msg.Command = "Sync"
	case 'H': // Flush
		parsedData = PostgresMessage{Type: "Flush"}
		msg.Command = "Flush"
	default:
		// 处理启动消息
		if msgType == 0x00 {
			parsedData, err = p.parseStartupMessage(data)
			msg.Command = "Startup"
		} else {
			parsedData = PostgresMessage{
				Type: "Unknown",
				Data: map[string]interface{}{"raw": data},
			}
			msg.Command = "Unknown"
		}
	}

	if err != nil {
		return nil, fmt.Errorf("解析消息失败: %v", err)
	}

	msg.ParsedData = parsedData
	msg.ID = p.generateRequestID(msg.Command, parsedData)

	return msg, nil
}

// ParseResponse 解析响应
func (p *PostgresParser) ParseResponse(data []byte) (*types.Message, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("数据包太短")
	}

	msg := &types.Message{
		Type:      "response",
		Data:      data,
		Size:      len(data),
		Timestamp: time.Now(),
	}

	msgType := data[0]
	length := binary.BigEndian.Uint32(data[1:5])

	var parsedData PostgresMessage
	var err error

	switch msgType {
	case 'R': // Authentication
		parsedData, err = p.parseAuthentication(data[5 : length+1])
		msg.Command = "Authentication"
	case 'K': // BackendKeyData
		parsedData, err = p.parseBackendKeyData(data[5 : length+1])
		msg.Command = "BackendKeyData"
	case 'S': // ParameterStatus
		parsedData, err = p.parseParameterStatus(data[5 : length+1])
		msg.Command = "ParameterStatus"
	case 'Z': // ReadyForQuery
		parsedData, err = p.parseReadyForQuery(data[5 : length+1])
		msg.Command = "ReadyForQuery"
	case 'T': // RowDescription
		parsedData, err = p.parseRowDescription(data[5 : length+1])
		msg.Command = "RowDescription"
	case 'D': // DataRow
		parsedData, err = p.parseDataRow(data[5 : length+1])
		msg.Command = "DataRow"
	case 'C': // CommandComplete
		parsedData, err = p.parseCommandComplete(data[5 : length+1])
		msg.Command = "CommandComplete"
	case 'E': // ErrorResponse
		parsedData, err = p.parseErrorResponse(data[5 : length+1])
		msg.Command = "ErrorResponse"
	case 'N': // NoticeResponse
		parsedData, err = p.parseNoticeResponse(data[5 : length+1])
		msg.Command = "NoticeResponse"
	case '1': // ParseComplete
		parsedData = PostgresMessage{Type: "ParseComplete"}
		msg.Command = "ParseComplete"
	case '2': // BindComplete
		parsedData = PostgresMessage{Type: "BindComplete"}
		msg.Command = "BindComplete"
	case '3': // CloseComplete
		parsedData = PostgresMessage{Type: "CloseComplete"}
		msg.Command = "CloseComplete"
	case 'n': // NoData
		parsedData = PostgresMessage{Type: "NoData"}
		msg.Command = "NoData"
	case 'I': // EmptyQueryResponse
		parsedData = PostgresMessage{Type: "EmptyQueryResponse"}
		msg.Command = "EmptyQueryResponse"
	default:
		parsedData = PostgresMessage{
			Type: "Unknown",
			Data: map[string]interface{}{"raw": data},
		}
		msg.Command = "Unknown"
	}

	if err != nil {
		return nil, fmt.Errorf("解析响应失败: %v", err)
	}

	msg.ParsedData = parsedData
	msg.ID = p.generateResponseID(msg.Command, parsedData)

	return msg, nil
}

// PostgresMessage PostgreSQL消息结构
type PostgresMessage struct {
	Type string                 `json:"type"`
	Data map[string]interface{} `json:"data"`
}

// parseQuery 解析Query消息
func (p *PostgresParser) parseQuery(data []byte) (PostgresMessage, error) {
	// Query消息包含一个以null结尾的SQL字符串
	sql := string(data[:len(data)-1]) // 去掉最后的null字节
	return PostgresMessage{
		Type: "Query",
		Data: map[string]interface{}{
			"sql": sql,
		},
	}, nil
}

// parseParse 解析Parse消息
func (p *PostgresParser) parseParse(data []byte) (PostgresMessage, error) {
	// Parse消息格式: 语句名(null结尾) + SQL(null结尾) + 参数类型数量(2字节) + 参数类型OIDs
	pos := 0

	// 读取语句名
	stmtNameEnd := p.findNullTerminator(data[pos:])
	stmtName := string(data[pos : pos+stmtNameEnd])
	pos += stmtNameEnd + 1

	// 读取SQL
	sqlEnd := p.findNullTerminator(data[pos:])
	sql := string(data[pos : pos+sqlEnd])
	pos += sqlEnd + 1

	// 读取参数类型数量
	var paramCount uint16
	if pos+2 <= len(data) {
		paramCount = binary.BigEndian.Uint16(data[pos : pos+2])
		pos += 2
	}

	return PostgresMessage{
		Type: "Parse",
		Data: map[string]interface{}{
			"statement_name": stmtName,
			"sql":            sql,
			"param_count":    paramCount,
		},
	}, nil
}

// parseBind 解析Bind消息
func (p *PostgresParser) parseBind(data []byte) (PostgresMessage, error) {
	pos := 0

	// 读取portal名
	portalNameEnd := p.findNullTerminator(data[pos:])
	portalName := string(data[pos : pos+portalNameEnd])
	pos += portalNameEnd + 1

	// 读取语句名
	stmtNameEnd := p.findNullTerminator(data[pos:])
	stmtName := string(data[pos : pos+stmtNameEnd])
	pos += stmtNameEnd + 1

	return PostgresMessage{
		Type: "Bind",
		Data: map[string]interface{}{
			"portal_name":    portalName,
			"statement_name": stmtName,
		},
	}, nil
}

// parseExecute 解析Execute消息
func (p *PostgresParser) parseExecute(data []byte) (PostgresMessage, error) {
	pos := 0

	// 读取portal名
	portalNameEnd := p.findNullTerminator(data[pos:])
	portalName := string(data[pos : pos+portalNameEnd])
	pos += portalNameEnd + 1

	// 读取最大行数
	var maxRows uint32
	if pos+4 <= len(data) {
		maxRows = binary.BigEndian.Uint32(data[pos : pos+4])
	}

	return PostgresMessage{
		Type: "Execute",
		Data: map[string]interface{}{
			"portal_name": portalName,
			"max_rows":    maxRows,
		},
	}, nil
}

// parseDescribe 解析Describe消息
func (p *PostgresParser) parseDescribe(data []byte) (PostgresMessage, error) {
	if len(data) < 1 {
		return PostgresMessage{}, fmt.Errorf("Describe消息太短")
	}

	descType := string(data[0])           // 'S' for statement, 'P' for portal
	name := string(data[1 : len(data)-1]) // 去掉最后的null字节

	return PostgresMessage{
		Type: "Describe",
		Data: map[string]interface{}{
			"describe_type": descType,
			"name":          name,
		},
	}, nil
}

// parseClose 解析Close消息
func (p *PostgresParser) parseClose(data []byte) (PostgresMessage, error) {
	if len(data) < 1 {
		return PostgresMessage{}, fmt.Errorf("Close消息太短")
	}

	closeType := string(data[0])          // 'S' for statement, 'P' for portal
	name := string(data[1 : len(data)-1]) // 去掉最后的null字节

	return PostgresMessage{
		Type: "Close",
		Data: map[string]interface{}{
			"close_type": closeType,
			"name":       name,
		},
	}, nil
}

// parseStartupMessage 解析启动消息
func (p *PostgresParser) parseStartupMessage(data []byte) (PostgresMessage, error) {
	if len(data) < 8 {
		return PostgresMessage{}, fmt.Errorf("启动消息太短")
	}

	length := binary.BigEndian.Uint32(data[0:4])
	version := binary.BigEndian.Uint32(data[4:8])

	params := make(map[string]string)
	pos := 8

	for pos < int(length)-1 {
		// 读取参数名
		keyEnd := p.findNullTerminator(data[pos:])
		if keyEnd == -1 {
			break
		}
		key := string(data[pos : pos+keyEnd])
		pos += keyEnd + 1

		// 读取参数值
		valueEnd := p.findNullTerminator(data[pos:])
		if valueEnd == -1 {
			break
		}
		value := string(data[pos : pos+valueEnd])
		pos += valueEnd + 1

		params[key] = value
	}

	return PostgresMessage{
		Type: "StartupMessage",
		Data: map[string]interface{}{
			"version":    version,
			"parameters": params,
		},
	}, nil
}

// parseAuthentication 解析Authentication消息
func (p *PostgresParser) parseAuthentication(data []byte) (PostgresMessage, error) {
	if len(data) < 4 {
		return PostgresMessage{}, fmt.Errorf("Authentication消息太短")
	}

	authType := binary.BigEndian.Uint32(data[0:4])

	return PostgresMessage{
		Type: "Authentication",
		Data: map[string]interface{}{
			"auth_type": authType,
		},
	}, nil
}

// parseBackendKeyData 解析BackendKeyData消息
func (p *PostgresParser) parseBackendKeyData(data []byte) (PostgresMessage, error) {
	if len(data) < 8 {
		return PostgresMessage{}, fmt.Errorf("BackendKeyData消息太短")
	}

	processID := binary.BigEndian.Uint32(data[0:4])
	secretKey := binary.BigEndian.Uint32(data[4:8])

	return PostgresMessage{
		Type: "BackendKeyData",
		Data: map[string]interface{}{
			"process_id": processID,
			"secret_key": secretKey,
		},
	}, nil
}

// parseParameterStatus 解析ParameterStatus消息
func (p *PostgresParser) parseParameterStatus(data []byte) (PostgresMessage, error) {
	pos := 0

	// 读取参数名
	nameEnd := p.findNullTerminator(data[pos:])
	name := string(data[pos : pos+nameEnd])
	pos += nameEnd + 1

	// 读取参数值
	valueEnd := p.findNullTerminator(data[pos:])
	value := string(data[pos : pos+valueEnd])

	return PostgresMessage{
		Type: "ParameterStatus",
		Data: map[string]interface{}{
			"name":  name,
			"value": value,
		},
	}, nil
}

// parseReadyForQuery 解析ReadyForQuery消息
func (p *PostgresParser) parseReadyForQuery(data []byte) (PostgresMessage, error) {
	if len(data) < 1 {
		return PostgresMessage{}, fmt.Errorf("ReadyForQuery消息太短")
	}

	status := string(data[0])

	return PostgresMessage{
		Type: "ReadyForQuery",
		Data: map[string]interface{}{
			"status": status, // 'I'=idle, 'T'=transaction, 'E'=error
		},
	}, nil
}

// parseRowDescription 解析RowDescription消息
func (p *PostgresParser) parseRowDescription(data []byte) (PostgresMessage, error) {
	if len(data) < 2 {
		return PostgresMessage{}, fmt.Errorf("RowDescription消息太短")
	}

	fieldCount := binary.BigEndian.Uint16(data[0:2])

	return PostgresMessage{
		Type: "RowDescription",
		Data: map[string]interface{}{
			"field_count": fieldCount,
		},
	}, nil
}

// parseDataRow 解析DataRow消息
func (p *PostgresParser) parseDataRow(data []byte) (PostgresMessage, error) {
	if len(data) < 2 {
		return PostgresMessage{}, fmt.Errorf("DataRow消息太短")
	}

	fieldCount := binary.BigEndian.Uint16(data[0:2])

	return PostgresMessage{
		Type: "DataRow",
		Data: map[string]interface{}{
			"field_count": fieldCount,
		},
	}, nil
}

// parseCommandComplete 解析CommandComplete消息
func (p *PostgresParser) parseCommandComplete(data []byte) (PostgresMessage, error) {
	tag := string(data[:len(data)-1]) // 去掉最后的null字节

	return PostgresMessage{
		Type: "CommandComplete",
		Data: map[string]interface{}{
			"command_tag": tag,
		},
	}, nil
}

// parseErrorResponse 解析ErrorResponse消息
func (p *PostgresParser) parseErrorResponse(data []byte) (PostgresMessage, error) {
	fields := make(map[string]string)
	pos := 0

	for pos < len(data)-1 { // -1 for final null terminator
		if pos >= len(data) {
			break
		}

		fieldType := string(data[pos])
		pos++

		// 读取字段值
		valueEnd := p.findNullTerminator(data[pos:])
		if valueEnd == -1 {
			break
		}
		value := string(data[pos : pos+valueEnd])
		pos += valueEnd + 1

		fields[fieldType] = value
	}

	return PostgresMessage{
		Type: "ErrorResponse",
		Data: map[string]interface{}{
			"fields": fields,
		},
	}, nil
}

// parseNoticeResponse 解析NoticeResponse消息
func (p *PostgresParser) parseNoticeResponse(data []byte) (PostgresMessage, error) {
	return p.parseErrorResponse(data) // 格式相同
}

// 辅助函数
func (p *PostgresParser) findNullTerminator(data []byte) int {
	for i, b := range data {
		if b == 0 {
			return i
		}
	}
	return -1
}

// generateRequestID 生成请求ID
func (p *PostgresParser) generateRequestID(command string, msg PostgresMessage) string {
	switch command {
	case "Query":
		if sql, ok := msg.Data["sql"].(string); ok {
			// 提取SQL命令类型
			parts := strings.Fields(strings.ToUpper(sql))
			if len(parts) > 0 {
				return fmt.Sprintf("query_%s_%d", parts[0], time.Now().UnixNano())
			}
		}
	case "Parse":
		if stmtName, ok := msg.Data["statement_name"].(string); ok {
			return fmt.Sprintf("parse_%s_%d", stmtName, time.Now().UnixNano())
		}
	case "Execute":
		if portalName, ok := msg.Data["portal_name"].(string); ok {
			return fmt.Sprintf("exec_%s_%d", portalName, time.Now().UnixNano())
		}
	}

	return fmt.Sprintf("%s_%d", command, time.Now().UnixNano())
}

// generateResponseID 生成响应ID
func (p *PostgresParser) generateResponseID(command string, msg PostgresMessage) string {
	return fmt.Sprintf("resp_%s_%d", command, time.Now().UnixNano())
}
