package main

import (
	"fmt"
	"time"

	"github.com/myserver/go-server/ebpf/middle/parsers"
	"github.com/myserver/go-server/ebpf/middle/types"
)

func main() {
	fmt.Println("=== 测试Redis消息解析逻辑 ===")

	// 创建Redis高级解析器
	config := &parsers.RedisAdvancedConfig{
		MaxContentLength:    64,
		EnableDBTracking:    true,
		SessionTimeout:      30 * time.Second,
		EnableDetailedStats: true,
		Verbose:             true,
	}

	adapter := parsers.NewRedisAdvancedParserAdapter(config)

	// 模拟连接信息
	conn := &types.Connection{
		LocalAddr:  "192.168.2.11:50698",
		RemoteAddr: "192.168.2.226:6379",
		Direction:  types.DirectionOutbound,
		StartTime:  time.Now(),
	}

	fmt.Println("\n1. 测试请求解析：")

	// 测试SET命令
	setCmd := []byte("*3\r\n$3\r\nSET\r\n$2\r\nk1\r\n$7\r\nmyvalue\r\n")
	fmt.Printf("SET命令原始数据: %q\n", string(setCmd))

	if adapter.IsRequest(setCmd) {
		fmt.Println("✅ 正确识别为请求")

		if reqMsg, err := adapter.ParseRequest(setCmd); err == nil {
			reqMsg.Connection = conn
			reqMsg.Timestamp = time.Now()
			fmt.Printf("✅ 解析成功: Command=%s, ID=%s\n", reqMsg.Command, reqMsg.ID)

			// 手动注册请求
			if parsedCmd, ok := reqMsg.ParsedData.(*parsers.RedisParsedCommand); ok {
				adapter.GetParser().RegisterRequestManually(reqMsg, parsedCmd)
				fmt.Printf("✅ 请求已注册: Key=%s, Value=%s\n", parsedCmd.Key, parsedCmd.Value)
			}
		} else {
			fmt.Printf("❌ 解析失败: %v\n", err)
		}
	} else {
		fmt.Println("❌ 未识别为请求")
	}

	fmt.Println("\n2. 测试响应解析：")

	// 测试OK响应
	okResp := []byte("+OK\r\n")
	fmt.Printf("OK响应原始数据: %q\n", string(okResp))

	if adapter.IsResponse(okResp) {
		fmt.Println("✅ 正确识别为响应")

		if respMsg, err := adapter.ParseResponse(okResp); err == nil {
			respMsg.Connection = conn
			respMsg.Timestamp = time.Now()
			fmt.Printf("✅ 解析成功: Command=%s, ID=%s\n", respMsg.Command, respMsg.ID)

			// 尝试匹配请求响应
			if rr := adapter.MatchRequestResponse(respMsg); rr != nil {
				fmt.Println("✅ 成功匹配请求响应!")
				formatted := adapter.FormatRequestResponse(rr)
				fmt.Printf("格式化输出: %s\n", formatted)
			} else {
				fmt.Println("❌ 未找到匹配的请求")
			}
		} else {
			fmt.Printf("❌ 解析失败: %v\n", err)
		}
	} else {
		fmt.Println("❌ 未识别为响应")
	}

	fmt.Println("\n3. 测试GET命令：")

	// 测试GET命令
	getCmd := []byte("*2\r\n$3\r\nGET\r\n$2\r\nk1\r\n")
	fmt.Printf("GET命令原始数据: %q\n", string(getCmd))

	if reqMsg, err := adapter.ParseRequest(getCmd); err == nil {
		reqMsg.Connection = conn
		reqMsg.Timestamp = time.Now()

		if parsedCmd, ok := reqMsg.ParsedData.(*parsers.RedisParsedCommand); ok {
			adapter.GetParser().RegisterRequestManually(reqMsg, parsedCmd)
			fmt.Printf("✅ GET请求已注册: Key=%s\n", parsedCmd.Key)
		}
	}

	// 测试批量字符串响应
	bulkResp := []byte("$7\r\nmyvalue\r\n")
	fmt.Printf("批量字符串响应原始数据: %q\n", string(bulkResp))

	if respMsg, err := adapter.ParseResponse(bulkResp); err == nil {
		respMsg.Connection = conn
		respMsg.Timestamp = time.Now()

		if rr := adapter.MatchRequestResponse(respMsg); rr != nil {
			fmt.Println("✅ GET响应成功匹配!")
			formatted := adapter.FormatRequestResponse(rr)
			fmt.Printf("格式化输出: %s\n", formatted)
		} else {
			fmt.Println("❌ GET响应未找到匹配的请求")
		}
	}

	fmt.Println("\n=== 测试完成 ===")
}
