// Package parsers - RocketMQ协议解析器 (自定义协议)
package parsers

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/myserver/go-server/ebpf/middle/types"
)

// RocketMQParser RocketMQ协议解析器
type RocketMQParser struct{}

// NewRocketMQParser 创建RocketMQ解析器
func NewRocketMQParser() *RocketMQParser {
	return &RocketMQParser{}
}

// GetProtocol 获取协议名称
func (p *RocketMQParser) GetProtocol() string {
	return "rocketmq"
}

// GetDefaultPort 获取默认端口
func (p *RocketMQParser) GetDefaultPort() int {
	return 10911 // NameServer默认端口，Broker默认10909
}

// RocketMQ协议常量
const (
	// 请求类型码
	SEND_MESSAGE                         = 10
	PULL_MESSAGE                         = 11
	QUERY_MESSAGE                        = 12
	QUERY_BROKER_OFFSET                  = 13
	QUERY_CONSUMER_OFFSET                = 14
	UPDATE_CONSUMER_OFFSET               = 15
	UPDATE_AND_CREATE_TOPIC              = 17
	GET_ALL_TOPIC_CONFIG                 = 21
	GET_TOPIC_CONFIG_LIST                = 22
	GET_TOPIC_NAME_LIST                  = 23
	UPDATE_BROKER_CONFIG                 = 25
	GET_BROKER_CONFIG                    = 26
	TRIGGER_DELETE_FILES                 = 27
	GET_BROKER_RUNTIME_INFO              = 28
	SEARCH_OFFSET_BY_TIMESTAMP           = 29
	GET_MAX_OFFSET                       = 30
	GET_MIN_OFFSET                       = 31
	GET_EARLIEST_MSG_STORETIME           = 32
	VIEW_MESSAGE_BY_ID                   = 33
	HEART_BEAT                           = 34
	UNREGISTER_CLIENT                    = 35
	CONSUMER_SEND_MSG_BACK               = 36
	END_TRANSACTION                      = 37
	GET_CONSUMER_LIST_BY_GROUP           = 38
	CHECK_TRANSACTION_STATE              = 39
	NOTIFY_CONSUMER_IDS_CHANGED          = 40
	LOCK_BATCH_MQ                        = 41
	UNLOCK_BATCH_MQ                      = 42
	GET_ALL_CONSUMER_OFFSET              = 43
	GET_ALL_DELAY_OFFSET                 = 45
	CHECK_CLIENT_CONFIG                  = 46
	UPDATE_AND_CREATE_ACL_CONFIG         = 50
	DELETE_ACL_CONFIG                    = 51
	GET_BROKER_CLUSTER_ACL_INFO          = 52
	UPDATE_GLOBAL_WHITE_ADDRS_CONFIG     = 53
	GET_BROKER_CLUSTER_ACL_CONFIG        = 54
	PUT_KV_CONFIG                        = 100
	GET_KV_CONFIG                        = 101
	DELETE_KV_CONFIG                     = 102
	REGISTER_BROKER                      = 103
	UNREGISTER_BROKER                    = 104
	GET_ROUTEINTO_BY_TOPIC               = 105
	GET_BROKER_CLUSTER_INFO              = 106
	UPDATE_AND_CREATE_SUBSCRIPTIONGROUP  = 200
	GET_ALL_SUBSCRIPTIONGROUP_CONFIG     = 201
	GET_TOPIC_STATS_INFO                 = 202
	GET_CONSUMER_CONNECTION_LIST         = 203
	GET_PRODUCER_CONNECTION_LIST         = 204
	WIPE_WRITE_PERM_OF_BROKER            = 205
	GET_ALL_TOPIC_LIST_FROM_NAMESERVER   = 206
	DELETE_SUBSCRIPTIONGROUP             = 207
	GET_CONSUME_STATS                    = 208
	SUSPEND_CONSUMER                     = 209
	RESUME_CONSUMER                      = 210
	RESET_CONSUMER_OFFSET_IN_CONSUMER    = 211
	RESET_CONSUMER_OFFSET_IN_BROKER      = 212
	ADJUST_CONSUMER_THREAD_POOL          = 213
	WHO_CONSUME_THE_MESSAGE              = 214
	DELETE_TOPIC_IN_BROKER               = 215
	DELETE_TOPIC_IN_NAMESRV              = 216
	GET_KV_CONFIG_BY_VALUE               = 217
	DELETE_KV_CONFIG_BY_VALUE            = 218
	GET_KV_LIST_BY_NAMESPACE             = 219
	RESET_CONSUMER_CLIENT_OFFSET         = 220
	GET_CONSUMER_STATUS_FROM_CLIENT      = 221
	INVOKE_BROKER_TO_RESET_OFFSET        = 222
	INVOKE_BROKER_TO_GET_CONSUMER_STATUS = 223
	QUERY_TOPIC_CONSUME_BY_WHO           = 300
	GET_TOPICS_BY_CLUSTER                = 224
	REGISTER_FILTER_SERVER               = 301
	REGISTER_MESSAGE_FILTER_CLASS        = 302
	QUERY_CONSUME_TIME_SPAN              = 303
	GET_SYSTEM_TOPIC_LIST_FROM_NS        = 304
	GET_SYSTEM_TOPIC_LIST_FROM_BROKER    = 305
	CLEAN_EXPIRED_CONSUMEQUEUE           = 306
	GET_CONSUMER_RUNNING_INFO            = 307
	QUERY_CORRECTION_OFFSET              = 308
	CONSUME_MESSAGE_DIRECTLY             = 309
	SEND_MESSAGE_V2                      = 310
	UNIT_SUB_GROUP                       = 311
	GET_UNIT_TOP_SUB                     = 312
	GET_HAS_UNIT_SUB_TOPIC_LIST          = 313
	GET_HAS_UNIT_SUB_UNUNIT_TOPIC_LIST   = 314
	CLONE_GROUP_OFFSET                   = 315
	VIEW_BROKER_STATS_DATA               = 316
	CLEAN_UNUSED_TOPIC                   = 317
	GET_BROKER_CONSUME_STATS             = 318
	UPDATE_NAMESRV_CONFIG                = 318
	GET_NAMESRV_CONFIG                   = 319
)

// IsRequest 判断是否为请求
func (p *RocketMQParser) IsRequest(data []byte) bool {
	if len(data) < 16 {
		return false
	}

	// RocketMQ协议格式：长度(4) + 序列化类型和头部长度(4) + 头部数据 + 消息体
	totalLength := binary.BigEndian.Uint32(data[0:4])
	if totalLength > uint32(len(data)) {
		return false
	}

	headerData := binary.BigEndian.Uint32(data[4:8])
	serializeType := (headerData >> 24) & 0xFF
	headerLength := headerData & 0xFFFFFF

	// 检查序列化类型是否有效（0=JSON, 1=ROCKETMQ）
	if serializeType != 0 && serializeType != 1 {
		return false
	}

	// 检查头部长度是否合理
	if headerLength == 0 || headerLength > totalLength {
		return false
	}

	// 提取头部JSON
	if 8+int(headerLength) > len(data) {
		return false
	}

	headerBytes := data[8 : 8+headerLength]
	var header RocketMQHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return false
	}

	// 根据请求码判断是否为请求
	return p.isRequestCode(header.Code)
}

// IsResponse 判断是否为响应
func (p *RocketMQParser) IsResponse(data []byte) bool {
	if len(data) < 16 {
		return false
	}

	totalLength := binary.BigEndian.Uint32(data[0:4])
	if totalLength > uint32(len(data)) {
		return false
	}

	headerData := binary.BigEndian.Uint32(data[4:8])
	serializeType := (headerData >> 24) & 0xFF
	headerLength := headerData & 0xFFFFFF

	if serializeType != 0 && serializeType != 1 {
		return false
	}

	if headerLength == 0 || headerLength > totalLength {
		return false
	}

	if 8+int(headerLength) > len(data) {
		return false
	}

	headerBytes := data[8 : 8+headerLength]
	var header RocketMQHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return false
	}

	// 响应通常有ResponseCode字段或者Flag标记
	return header.Flag&0x01 == 0x01 // 响应标志位
}

// ParseRequest 解析请求
func (p *RocketMQParser) ParseRequest(data []byte) (*types.Message, error) {
	if len(data) < 16 {
		return nil, fmt.Errorf("RocketMQ数据包太短")
	}

	msg := &types.Message{
		Type:      "request",
		Data:      data,
		Size:      len(data),
		Timestamp: time.Now(),
	}

	rmqMsg, err := p.parseRocketMQMessage(data)
	if err != nil {
		return nil, fmt.Errorf("解析RocketMQ消息失败: %v", err)
	}

	msg.ParsedData = rmqMsg
	msg.Command = p.getRequestName(rmqMsg.Header.Code)
	msg.ID = p.generateRequestID(rmqMsg)

	return msg, nil
}

// ParseResponse 解析响应
func (p *RocketMQParser) ParseResponse(data []byte) (*types.Message, error) {
	if len(data) < 16 {
		return nil, fmt.Errorf("RocketMQ数据包太短")
	}

	msg := &types.Message{
		Type:      "response",
		Data:      data,
		Size:      len(data),
		Timestamp: time.Now(),
	}

	rmqMsg, err := p.parseRocketMQMessage(data)
	if err != nil {
		return nil, fmt.Errorf("解析RocketMQ响应失败: %v", err)
	}

	msg.ParsedData = rmqMsg
	msg.Command = "Response"
	if rmqMsg.Header.Code != 0 {
		msg.Command = p.getRequestName(rmqMsg.Header.Code) + "_Response"
	}
	msg.ID = p.generateResponseID(rmqMsg)

	return msg, nil
}

// RocketMQMessage RocketMQ消息结构
type RocketMQMessage struct {
	TotalLength   uint32         `json:"total_length"`
	SerializeType uint8          `json:"serialize_type"`
	HeaderLength  uint32         `json:"header_length"`
	Header        RocketMQHeader `json:"header"`
	Body          []byte         `json:"body,omitempty"`
}

// RocketMQHeader RocketMQ头部结构
type RocketMQHeader struct {
	Code      int                    `json:"code"`
	Language  string                 `json:"language,omitempty"`
	Version   int                    `json:"version,omitempty"`
	Opaque    int                    `json:"opaque"`
	Flag      int                    `json:"flag"`
	Remark    string                 `json:"remark,omitempty"`
	ExtFields map[string]interface{} `json:"extFields,omitempty"`
}

// parseRocketMQMessage 解析RocketMQ消息
func (p *RocketMQParser) parseRocketMQMessage(data []byte) (*RocketMQMessage, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("数据太短")
	}

	// 解析总长度
	totalLength := binary.BigEndian.Uint32(data[0:4])

	// 解析序列化类型和头部长度
	headerData := binary.BigEndian.Uint32(data[4:8])
	serializeType := uint8((headerData >> 24) & 0xFF)
	headerLength := headerData & 0xFFFFFF

	if 8+int(headerLength) > len(data) {
		return nil, fmt.Errorf("头部长度超出数据范围")
	}

	// 解析头部
	headerBytes := data[8 : 8+headerLength]
	var header RocketMQHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("解析头部JSON失败: %v", err)
	}

	// 解析消息体
	var body []byte
	bodyStart := 8 + int(headerLength)
	if bodyStart < len(data) {
		body = data[bodyStart:]
	}

	return &RocketMQMessage{
		TotalLength:   totalLength,
		SerializeType: serializeType,
		HeaderLength:  headerLength,
		Header:        header,
		Body:          body,
	}, nil
}

// isRequestCode 判断是否为请求码
func (p *RocketMQParser) isRequestCode(code int) bool {
	// 常见的请求码
	requestCodes := map[int]bool{
		SEND_MESSAGE:               true,
		PULL_MESSAGE:               true,
		QUERY_MESSAGE:              true,
		HEART_BEAT:                 true,
		REGISTER_BROKER:            true,
		UNREGISTER_BROKER:          true,
		GET_ROUTEINTO_BY_TOPIC:     true,
		GET_BROKER_CLUSTER_INFO:    true,
		SEND_MESSAGE_V2:            true,
		CONSUMER_SEND_MSG_BACK:     true,
		END_TRANSACTION:            true,
		GET_CONSUMER_LIST_BY_GROUP: true,
		LOCK_BATCH_MQ:              true,
		UNLOCK_BATCH_MQ:            true,
		UPDATE_CONSUMER_OFFSET:     true,
		QUERY_CONSUMER_OFFSET:      true,
		UPDATE_AND_CREATE_TOPIC:    true,
		GET_ALL_TOPIC_CONFIG:       true,
	}

	return requestCodes[code]
}

// getRequestName 获取请求名称
func (p *RocketMQParser) getRequestName(code int) string {
	requestNames := map[int]string{
		SEND_MESSAGE:                        "SendMessage",
		PULL_MESSAGE:                        "PullMessage",
		QUERY_MESSAGE:                       "QueryMessage",
		QUERY_BROKER_OFFSET:                 "QueryBrokerOffset",
		QUERY_CONSUMER_OFFSET:               "QueryConsumerOffset",
		UPDATE_CONSUMER_OFFSET:              "UpdateConsumerOffset",
		UPDATE_AND_CREATE_TOPIC:             "UpdateAndCreateTopic",
		GET_ALL_TOPIC_CONFIG:                "GetAllTopicConfig",
		GET_TOPIC_CONFIG_LIST:               "GetTopicConfigList",
		GET_TOPIC_NAME_LIST:                 "GetTopicNameList",
		UPDATE_BROKER_CONFIG:                "UpdateBrokerConfig",
		GET_BROKER_CONFIG:                   "GetBrokerConfig",
		TRIGGER_DELETE_FILES:                "TriggerDeleteFiles",
		GET_BROKER_RUNTIME_INFO:             "GetBrokerRuntimeInfo",
		SEARCH_OFFSET_BY_TIMESTAMP:          "SearchOffsetByTimestamp",
		GET_MAX_OFFSET:                      "GetMaxOffset",
		GET_MIN_OFFSET:                      "GetMinOffset",
		GET_EARLIEST_MSG_STORETIME:          "GetEarliestMsgStoretime",
		VIEW_MESSAGE_BY_ID:                  "ViewMessageById",
		HEART_BEAT:                          "HeartBeat",
		UNREGISTER_CLIENT:                   "UnregisterClient",
		CONSUMER_SEND_MSG_BACK:              "ConsumerSendMsgBack",
		END_TRANSACTION:                     "EndTransaction",
		GET_CONSUMER_LIST_BY_GROUP:          "GetConsumerListByGroup",
		CHECK_TRANSACTION_STATE:             "CheckTransactionState",
		NOTIFY_CONSUMER_IDS_CHANGED:         "NotifyConsumerIdsChanged",
		LOCK_BATCH_MQ:                       "LockBatchMQ",
		UNLOCK_BATCH_MQ:                     "UnlockBatchMQ",
		GET_ALL_CONSUMER_OFFSET:             "GetAllConsumerOffset",
		REGISTER_BROKER:                     "RegisterBroker",
		UNREGISTER_BROKER:                   "UnregisterBroker",
		GET_ROUTEINTO_BY_TOPIC:              "GetRouteInfoByTopic",
		GET_BROKER_CLUSTER_INFO:             "GetBrokerClusterInfo",
		SEND_MESSAGE_V2:                     "SendMessageV2",
		UPDATE_AND_CREATE_SUBSCRIPTIONGROUP: "UpdateAndCreateSubscriptionGroup",
		GET_ALL_SUBSCRIPTIONGROUP_CONFIG:    "GetAllSubscriptionGroupConfig",
		GET_TOPIC_STATS_INFO:                "GetTopicStatsInfo",
		GET_CONSUMER_CONNECTION_LIST:        "GetConsumerConnectionList",
		GET_PRODUCER_CONNECTION_LIST:        "GetProducerConnectionList",
		WIPE_WRITE_PERM_OF_BROKER:           "WipeWritePermOfBroker",
		GET_ALL_TOPIC_LIST_FROM_NAMESERVER:  "GetAllTopicListFromNameserver",
		DELETE_SUBSCRIPTIONGROUP:            "DeleteSubscriptionGroup",
		GET_CONSUME_STATS:                   "GetConsumeStats",
		SUSPEND_CONSUMER:                    "SuspendConsumer",
		RESUME_CONSUMER:                     "ResumeConsumer",
		RESET_CONSUMER_OFFSET_IN_CONSUMER:   "ResetConsumerOffsetInConsumer",
		RESET_CONSUMER_OFFSET_IN_BROKER:     "ResetConsumerOffsetInBroker",
		ADJUST_CONSUMER_THREAD_POOL:         "AdjustConsumerThreadPool",
		WHO_CONSUME_THE_MESSAGE:             "WhoConsumeTheMessage",
		DELETE_TOPIC_IN_BROKER:              "DeleteTopicInBroker",
		DELETE_TOPIC_IN_NAMESRV:             "DeleteTopicInNamesrv",
	}

	if name, exists := requestNames[code]; exists {
		return name
	}

	return fmt.Sprintf("Unknown_%d", code)
}

// generateRequestID 生成请求ID
func (p *RocketMQParser) generateRequestID(msg *RocketMQMessage) string {
	// 使用opaque作为主要标识符
	id := fmt.Sprintf("%s_%d", p.getRequestName(msg.Header.Code), msg.Header.Opaque)

	// 如果有扩展字段，尝试提取更多信息
	if msg.Header.ExtFields != nil {
		if topic, ok := msg.Header.ExtFields["topic"].(string); ok {
			id += "_" + topic
		}
		if consumerGroup, ok := msg.Header.ExtFields["consumerGroup"].(string); ok {
			id += "_" + consumerGroup
		}
		if msgId, ok := msg.Header.ExtFields["msgId"].(string); ok {
			id += "_" + msgId
		}
	}

	return id
}

// generateResponseID 生成响应ID
func (p *RocketMQParser) generateResponseID(msg *RocketMQMessage) string {
	return fmt.Sprintf("resp_%d_%d", msg.Header.Code, msg.Header.Opaque)
}

// ExtractMessageInfo 从消息体中提取消息信息
func (p *RocketMQParser) ExtractMessageInfo(body []byte, code int) map[string]interface{} {
	info := make(map[string]interface{})

	switch code {
	case SEND_MESSAGE, SEND_MESSAGE_V2:
		// 发送消息的body包含实际的消息内容
		if len(body) > 0 {
			info["message_body"] = string(body)
			info["message_size"] = len(body)
		}

	case PULL_MESSAGE:
		// 拉取消息的响应可能包含多条消息
		info["response_body_size"] = len(body)

	case HEART_BEAT:
		// 心跳消息通常包含客户端信息
		if len(body) > 0 {
			var heartbeatData map[string]interface{}
			if err := json.Unmarshal(body, &heartbeatData); err == nil {
				info["heartbeat_data"] = heartbeatData
			} else {
				info["heartbeat_raw"] = string(body)
			}
		}

	default:
		if len(body) > 0 {
			info["body_size"] = len(body)
			// 尝试解析为JSON
			var jsonData map[string]interface{}
			if err := json.Unmarshal(body, &jsonData); err == nil {
				info["json_data"] = jsonData
			} else {
				// 如果不是JSON，提供原始数据的预览
				preview := string(body)
				if len(preview) > 200 {
					preview = preview[:200] + "..."
				}
				info["body_preview"] = preview
			}
		}
	}

	return info
}

// IsErrorResponse 判断是否为错误响应
func (p *RocketMQParser) IsErrorResponse(msg *RocketMQMessage) bool {
	// RocketMQ响应码约定：0表示成功，非0表示失败
	if responseCode, ok := msg.Header.ExtFields["responseCode"].(float64); ok {
		return int(responseCode) != 0
	}

	// 检查Remark字段是否包含错误信息
	if msg.Header.Remark != "" && strings.Contains(strings.ToLower(msg.Header.Remark), "error") {
		return true
	}

	return false
}
