// Package parsers 提供各种中间件协议解析器
package parsers

import (
	"time"

	"github.com/myserver/go-server/ebpf/middle/types"
)

// GetParser 根据中间件类型获取对应的解析器
func GetParser(middleware string) types.ProtocolParser {
	return GetParserWithConfig(middleware, false) // 默认verbose=false
}

// GetParserWithConfig 根据中间件类型和配置获取对应的解析器
func GetParserWithConfig(middleware string, verbose bool) types.ProtocolParser {
	switch middleware {
	case "redis":
		config := &RedisAdvancedConfig{
			MaxContentLength:    64,
			EnableDBTracking:    true,
			SessionTimeout:      30 * time.Second,
			EnableDetailedStats: true,
			Verbose:             verbose,
		}
		return NewRedisAdvancedParserAdapter(config)
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
