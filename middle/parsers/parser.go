// Package parsers 提供各种中间件协议解析器
package parsers

import (
	"github.com/myserver/go-server/ebpf/middle/types"
)

// GetParser 根据中间件类型获取对应的解析器
func GetParser(middleware string) types.ProtocolParser {
	switch middleware {
	case "redis":
		return NewRedisParser()
	case "redis-enhanced":
		// 返回增强版Redis解析器，但需要适配接口
		config := &RedisParserConfig{
			MaxContentLength: 64,
			EnableDBTracking: true,
			Verbose:          false,
		}
		return NewRedisEnhancedParser(config)
	case "postgres":
		return NewPostgresParser()
	case "sqlserver":
		return NewSQLServerParser()
	case "minio":
		return NewMinIOParser()
	case "rocketmq":
		return NewRocketMQParser()
	default:
		return nil
	}
}
