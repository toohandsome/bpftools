// Package parsers - SQL Server协议解析器 (TDS协议)
package parsers

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/myserver/go-server/ebpf/middle/types"
)

// SQLServerParser SQL Server协议解析器
type SQLServerParser struct{}

// NewSQLServerParser 创建SQL Server解析器
func NewSQLServerParser() *SQLServerParser {
	return &SQLServerParser{}
}

// GetProtocol 获取协议名称
func (p *SQLServerParser) GetProtocol() string {
	return "sqlserver"
}

// GetDefaultPort 获取默认端口
func (p *SQLServerParser) GetDefaultPort() int {
	return 1433
}

// TDS包类型常量
const (
	TDS_TYPE_SQL_BATCH   = 0x01 // SQL批处理
	TDS_TYPE_PRE_TDS7    = 0x02 // Pre-TDS7登录
	TDS_TYPE_RPC         = 0x03 // 远程过程调用
	TDS_TYPE_TABULAR     = 0x04 // 表格响应
	TDS_TYPE_ATTENTION   = 0x06 // 注意信号
	TDS_TYPE_BULK_LOAD   = 0x07 // 批量加载数据
	TDS_TYPE_FED_AUTH    = 0x08 // 联合身份验证
	TDS_TYPE_TRANSACTION = 0x0E // 事务管理器请求
	TDS_TYPE_LOGIN7      = 0x10 // TDS7登录
	TDS_TYPE_SSPI        = 0x11 // SSPI消息
	TDS_TYPE_PRE_LOGIN   = 0x12 // Pre-login消息
)

// TDS状态常量
const (
	TDS_STATUS_NORMAL     = 0x00 // 正常
	TDS_STATUS_EOM        = 0x01 // 消息结束
	TDS_STATUS_IGNORE     = 0x02 // 忽略事件
	TDS_STATUS_RESETCON   = 0x08 // 重置连接
	TDS_STATUS_RESETCONSK = 0x10 // 重置连接，保持事务状态
)

// IsRequest 判断是否为请求
func (p *SQLServerParser) IsRequest(data []byte) bool {
	if len(data) < 8 {
		return false
	}

	msgType := data[0]

	// 客户端请求类型
	switch msgType {
	case TDS_TYPE_SQL_BATCH: // SQL批处理
		return true
	case TDS_TYPE_RPC: // 远程过程调用
		return true
	case TDS_TYPE_ATTENTION: // 注意信号
		return true
	case TDS_TYPE_BULK_LOAD: // 批量加载
		return true
	case TDS_TYPE_TRANSACTION: // 事务请求
		return true
	case TDS_TYPE_LOGIN7: // 登录请求
		return true
	case TDS_TYPE_PRE_LOGIN: // Pre-login请求
		return true
	case TDS_TYPE_SSPI: // SSPI消息
		return true
	default:
		return false
	}
}

// IsResponse 判断是否为响应
func (p *SQLServerParser) IsResponse(data []byte) bool {
	if len(data) < 8 {
		return false
	}

	msgType := data[0]

	// 服务端响应类型
	switch msgType {
	case TDS_TYPE_TABULAR: // 表格响应数据
		return true
	default:
		// 对于其他类型，需要通过状态位判断
		// 如果不是明确的请求类型，可能是响应
		return !p.IsRequest(data)
	}
}

// ParseRequest 解析请求
func (p *SQLServerParser) ParseRequest(data []byte) (*types.Message, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("TDS包太短")
	}

	header, err := p.parseTDSHeader(data)
	if err != nil {
		return nil, fmt.Errorf("解析TDS头失败: %v", err)
	}

	msg := &types.Message{
		Type:      "request",
		Data:      data,
		Size:      len(data),
		Timestamp: time.Now(),
	}

	var parsedData TDSMessage

	switch header.Type {
	case TDS_TYPE_SQL_BATCH:
		parsedData, err = p.parseSQLBatch(data[8:header.Length])
		msg.Command = "SQLBatch"
	case TDS_TYPE_RPC:
		parsedData, err = p.parseRPC(data[8:header.Length])
		msg.Command = "RPC"
	case TDS_TYPE_LOGIN7:
		parsedData, err = p.parseLogin7(data[8:header.Length])
		msg.Command = "Login7"
	case TDS_TYPE_PRE_LOGIN:
		parsedData, err = p.parsePreLogin(data[8:header.Length])
		msg.Command = "PreLogin"
	case TDS_TYPE_ATTENTION:
		parsedData = TDSMessage{
			Type:   "Attention",
			Header: *header,
		}
		msg.Command = "Attention"
	case TDS_TYPE_TRANSACTION:
		parsedData, err = p.parseTransaction(data[8:header.Length])
		msg.Command = "Transaction"
	default:
		parsedData = TDSMessage{
			Type:   "Unknown",
			Header: *header,
			Data:   map[string]interface{}{"raw": data[8:]},
		}
		msg.Command = "Unknown"
	}

	if err != nil {
		return nil, fmt.Errorf("解析TDS消息失败: %v", err)
	}

	msg.ParsedData = parsedData
	msg.ID = p.generateRequestID(msg.Command, parsedData)

	return msg, nil
}

// ParseResponse 解析响应
func (p *SQLServerParser) ParseResponse(data []byte) (*types.Message, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("TDS包太短")
	}

	header, err := p.parseTDSHeader(data)
	if err != nil {
		return nil, fmt.Errorf("解析TDS头失败: %v", err)
	}

	msg := &types.Message{
		Type:      "response",
		Data:      data,
		Size:      len(data),
		Timestamp: time.Now(),
	}

	var parsedData TDSMessage

	switch header.Type {
	case TDS_TYPE_TABULAR:
		parsedData, err = p.parseTabularResponse(data[8:header.Length])
		msg.Command = "TabularResponse"
	default:
		// 其他类型的响应
		parsedData = TDSMessage{
			Type:   "Response",
			Header: *header,
			Data:   map[string]interface{}{"raw": data[8:]},
		}
		msg.Command = "Response"
	}

	if err != nil {
		return nil, fmt.Errorf("解析TDS响应失败: %v", err)
	}

	msg.ParsedData = parsedData
	msg.ID = p.generateResponseID(msg.Command, parsedData)

	return msg, nil
}

// TDSHeader TDS包头结构
type TDSHeader struct {
	Type     uint8  // 包类型
	Status   uint8  // 状态
	Length   uint16 // 包长度
	SPID     uint16 // 服务器进程ID
	PacketID uint8  // 包ID
	Window   uint8  // 窗口
}

// TDSMessage TDS消息结构
type TDSMessage struct {
	Type   string                 `json:"type"`
	Header TDSHeader              `json:"header"`
	Data   map[string]interface{} `json:"data"`
}

// parseTDSHeader 解析TDS包头
func (p *SQLServerParser) parseTDSHeader(data []byte) (*TDSHeader, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("数据太短，无法包含TDS头")
	}

	return &TDSHeader{
		Type:     data[0],
		Status:   data[1],
		Length:   binary.BigEndian.Uint16(data[2:4]),
		SPID:     binary.BigEndian.Uint16(data[4:6]),
		PacketID: data[6],
		Window:   data[7],
	}, nil
}

// parseSQLBatch 解析SQL批处理
func (p *SQLServerParser) parseSQLBatch(data []byte) (TDSMessage, error) {
	if len(data) < 4 {
		return TDSMessage{}, fmt.Errorf("SQL批处理数据太短")
	}

	// SQL批处理格式：
	// - ALL_HEADERS (变长)
	// - SQL文本 (Unicode)

	// 读取ALL_HEADERS长度
	totalHeaderLength := binary.LittleEndian.Uint32(data[0:4])
	pos := 4 + int(totalHeaderLength)

	// 提取SQL文本 (UTF-16LE编码)
	sqlBytes := data[pos:]
	sql := p.utf16LEToString(sqlBytes)

	return TDSMessage{
		Type: "SQLBatch",
		Data: map[string]interface{}{
			"sql":                 sql,
			"total_header_length": totalHeaderLength,
		},
	}, nil
}

// parseRPC 解析远程过程调用
func (p *SQLServerParser) parseRPC(data []byte) (TDSMessage, error) {
	if len(data) < 4 {
		return TDSMessage{}, fmt.Errorf("RPC数据太短")
	}

	// RPC格式：
	// - ALL_HEADERS (变长)
	// - RPC名称
	// - 参数

	totalHeaderLength := binary.LittleEndian.Uint32(data[0:4])
	pos := 4 + int(totalHeaderLength)

	// 读取过程名长度和名称
	if pos+2 > len(data) {
		return TDSMessage{}, fmt.Errorf("RPC数据不完整")
	}

	nameLength := binary.LittleEndian.Uint16(data[pos : pos+2])
	pos += 2

	var procName string
	if nameLength > 0 && pos+int(nameLength*2) <= len(data) {
		procName = p.utf16LEToString(data[pos : pos+int(nameLength*2)])
	}

	return TDSMessage{
		Type: "RPC",
		Data: map[string]interface{}{
			"procedure_name":      procName,
			"total_header_length": totalHeaderLength,
		},
	}, nil
}

// parseLogin7 解析Login7消息
func (p *SQLServerParser) parseLogin7(data []byte) (TDSMessage, error) {
	if len(data) < 4 {
		return TDSMessage{}, fmt.Errorf("Login7数据太短")
	}

	// Login7包含固定部分和可变部分
	length := binary.LittleEndian.Uint32(data[0:4])

	return TDSMessage{
		Type: "Login7",
		Data: map[string]interface{}{
			"length": length,
			"raw":    fmt.Sprintf("%x", data[:min(32, len(data))]), // 显示前32字节的十六进制
		},
	}, nil
}

// parsePreLogin 解析PreLogin消息
func (p *SQLServerParser) parsePreLogin(data []byte) (TDSMessage, error) {
	options := make(map[string]interface{})
	pos := 0

	// PreLogin选项格式：选项类型(1) + 偏移(2) + 长度(2)
	for pos+5 <= len(data) {
		optionType := data[pos]
		offset := binary.BigEndian.Uint16(data[pos+1 : pos+3])
		length := binary.BigEndian.Uint16(data[pos+3 : pos+5])
		pos += 5

		if optionType == 0xFF { // 终止符
			break
		}

		optionName := p.getPreLoginOptionName(optionType)
		options[optionName] = map[string]interface{}{
			"type":   optionType,
			"offset": offset,
			"length": length,
		}
	}

	return TDSMessage{
		Type: "PreLogin",
		Data: map[string]interface{}{
			"options": options,
		},
	}, nil
}

// parseTransaction 解析事务请求
func (p *SQLServerParser) parseTransaction(data []byte) (TDSMessage, error) {
	if len(data) < 2 {
		return TDSMessage{}, fmt.Errorf("事务数据太短")
	}

	transType := binary.LittleEndian.Uint16(data[0:2])

	return TDSMessage{
		Type: "Transaction",
		Data: map[string]interface{}{
			"transaction_type": transType,
		},
	}, nil
}

// parseTabularResponse 解析表格响应
func (p *SQLServerParser) parseTabularResponse(data []byte) (TDSMessage, error) {
	tokens := make([]map[string]interface{}, 0)
	pos := 0

	for pos < len(data) {
		if pos >= len(data) {
			break
		}

		tokenType := data[pos]
		pos++

		token := map[string]interface{}{
			"type": tokenType,
			"name": p.getTokenName(tokenType),
		}

		// 根据token类型解析数据
		switch tokenType {
		case 0x81: // COLMETADATA
			// 列元数据，需要解析列信息
			if pos+2 <= len(data) {
				colCount := binary.LittleEndian.Uint16(data[pos : pos+2])
				token["column_count"] = colCount
				pos += 2
			}
		case 0xD1: // ROW
			// 行数据，复杂解析
			token["data"] = "row_data"
		case 0xFD: // DONE
			// 完成标记
			if pos+8 <= len(data) {
				status := binary.LittleEndian.Uint16(data[pos : pos+2])
				curCmd := binary.LittleEndian.Uint16(data[pos+2 : pos+4])
				rowCount := binary.LittleEndian.Uint32(data[pos+4 : pos+8])
				token["status"] = status
				token["current_command"] = curCmd
				token["row_count"] = rowCount
				pos += 8
			}
		default:
			// 跳过未知token
			pos = len(data)
		}

		tokens = append(tokens, token)
	}

	return TDSMessage{
		Type: "TabularResponse",
		Data: map[string]interface{}{
			"tokens": tokens,
		},
	}, nil
}

// 辅助函数
func (p *SQLServerParser) utf16LEToString(data []byte) string {
	// 简单的UTF-16LE到UTF-8转换
	if len(data)%2 != 0 {
		return ""
	}

	result := make([]rune, len(data)/2)
	for i := 0; i < len(data); i += 2 {
		if i+1 < len(data) {
			result[i/2] = rune(binary.LittleEndian.Uint16(data[i : i+2]))
		}
	}

	return string(result)
}

func (p *SQLServerParser) getPreLoginOptionName(optionType uint8) string {
	switch optionType {
	case 0x00:
		return "VERSION"
	case 0x01:
		return "ENCRYPTION"
	case 0x02:
		return "INSTOPT"
	case 0x03:
		return "THREADID"
	case 0x04:
		return "MARS"
	case 0x05:
		return "TRACEID"
	case 0x06:
		return "FEDAUTHREQUIRED"
	case 0x07:
		return "NONCEOPT"
	default:
		return fmt.Sprintf("UNKNOWN_%02X", optionType)
	}
}

func (p *SQLServerParser) getTokenName(tokenType uint8) string {
	switch tokenType {
	case 0x81:
		return "COLMETADATA"
	case 0xD1:
		return "ROW"
	case 0xFD:
		return "DONE"
	case 0xFE:
		return "DONEPROC"
	case 0xFF:
		return "DONEINPROC"
	case 0xAA:
		return "ERROR"
	case 0xAB:
		return "INFO"
	default:
		return fmt.Sprintf("TOKEN_%02X", tokenType)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// generateRequestID 生成请求ID
func (p *SQLServerParser) generateRequestID(command string, msg TDSMessage) string {
	switch command {
	case "SQLBatch":
		if sql, ok := msg.Data["sql"].(string); ok && len(sql) > 10 {
			return fmt.Sprintf("batch_%s_%d", sql[:10], time.Now().UnixNano())
		}
	case "RPC":
		if procName, ok := msg.Data["procedure_name"].(string); ok {
			return fmt.Sprintf("rpc_%s_%d", procName, time.Now().UnixNano())
		}
	}

	return fmt.Sprintf("%s_%d", command, time.Now().UnixNano())
}

// generateResponseID 生成响应ID
func (p *SQLServerParser) generateResponseID(command string, msg TDSMessage) string {
	return fmt.Sprintf("resp_%s_%d", command, time.Now().UnixNano())
}
