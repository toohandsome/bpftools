package main

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/myserver/go-server/ebpf/middle/parsers"
	"github.com/myserver/go-server/ebpf/middle/types"
)

func main() {
	fmt.Println("=== 测试并发Redis请求响应匹配 ===")

	// 创建Redis高级解析器
	config := &parsers.RedisAdvancedConfig{
		MaxContentLength:    64,
		EnableDBTracking:    true,
		SessionTimeout:      30 * time.Second,
		EnableDetailedStats: true,
		Verbose:             false, // 关闭详细日志避免混乱
	}

	// 为每个连接创建独立的解析器实例（模拟修复后的逻辑）
	createParserForConn := func(connAddr string) *parsers.RedisAdvancedParserAdapter {
		return parsers.NewRedisAdvancedParserAdapter(config)
	}

	// 模拟3个并发连接
	connections := []*types.Connection{
		{
			LocalAddr:  "192.168.2.11:50698",
			RemoteAddr: "192.168.2.226:6379",
			Direction:  types.DirectionOutbound,
			StartTime:  time.Now(),
		},
		{
			LocalAddr:  "192.168.2.11:50699",
			RemoteAddr: "192.168.2.226:6379",
			Direction:  types.DirectionOutbound,
			StartTime:  time.Now(),
		},
		{
			LocalAddr:  "192.168.2.11:50700",
			RemoteAddr: "192.168.2.226:6379",
			Direction:  types.DirectionOutbound,
			StartTime:  time.Now(),
		},
	}

	// 为每个连接创建独立的解析器
	parserAdapters := make([]*parsers.RedisAdvancedParserAdapter, len(connections))
	for i, conn := range connections {
		parserAdapters[i] = createParserForConn(conn.LocalAddr)
		fmt.Printf("为连接 %s 创建了独立解析器\n", conn.LocalAddr)
	}

	var wg sync.WaitGroup
	results := make([][]string, len(connections))

	// 模拟并发请求响应
	for i, conn := range connections {
		wg.Add(1)
		go func(connIndex int, connection *types.Connection, parser *parsers.RedisAdvancedParserAdapter) {
			defer wg.Done()

			connResults := []string{}

			// 每个连接发送多个请求
			requests := []struct {
				cmd      string
				data     []byte
				respData []byte
				respType string
			}{
				{"SET", []byte("*3\r\n$3\r\nSET\r\n$2\r\na1\r\n$6\r\nvalue1\r\n"), []byte("+OK\r\n"), "OK"},
				{"GET", []byte("*2\r\n$3\r\nGET\r\n$2\r\na1\r\n"), []byte("$6\r\nvalue1\r\n"), "value1"},
				{"SET", []byte("*3\r\n$3\r\nSET\r\n$2\r\nb1\r\n$6\r\nvalue2\r\n"), []byte("+OK\r\n"), "OK"},
				{"GET", []byte("*2\r\n$3\r\nGET\r\n$2\r\nb1\r\n"), []byte("$6\r\nvalue2\r\n"), "value2"},
			}

			for reqIndex, req := range requests {
				// 添加小延迟模拟网络延迟
				time.Sleep(time.Duration(connIndex*10+reqIndex*5) * time.Millisecond)

				// 处理请求
				if reqMsg, err := parser.ParseRequest(req.data); err == nil {
					reqMsg.Connection = connection
					reqMsg.Timestamp = time.Now()

					if parsedCmd, ok := reqMsg.ParsedData.(*parsers.RedisParsedCommand); ok {
						parser.GetParser().RegisterRequestManually(reqMsg, parsedCmd)
					}
				}

				// 添加响应延迟
				time.Sleep(time.Duration(5+connIndex*2) * time.Millisecond)

				// 处理响应
				if respMsg, err := parser.ParseResponse(req.respData); err == nil {
					respMsg.Connection = connection
					respMsg.Timestamp = time.Now()

					if rr := parser.MatchRequestResponse(respMsg); rr != nil {
						formatted := parser.FormatRequestResponse(rr)
						connResults = append(connResults, formatted)

						// 验证匹配是否正确
						expectedKey := fmt.Sprintf("%c1", 'a'+reqIndex/2)
						if rr.Request != nil && rr.Request.ParsedData != nil {
							if parsedCmd, ok := rr.Request.ParsedData.(*parsers.RedisParsedCommand); ok {
								if parsedCmd.Key == expectedKey {
									connResults = append(connResults, fmt.Sprintf("✅ 正确匹配: %s -> %s", req.cmd, req.respType))
								} else {
									connResults = append(connResults, fmt.Sprintf("❌ 错误匹配: 期望key=%s, 实际key=%s", expectedKey, parsedCmd.Key))
								}
							}
						}
					} else {
						connResults = append(connResults, fmt.Sprintf("❌ 未找到匹配: %s", req.cmd))
					}
				}
			}

			results[connIndex] = connResults
		}(i, conn, parserAdapters[i])
	}

	// 等待所有连接完成
	wg.Wait()

	// 打印结果
	fmt.Println("\n=== 并发测试结果 ===")
	for i, connResults := range results {
		fmt.Printf("\n连接 %d (%s):\n", i+1, connections[i].LocalAddr)
		for _, result := range connResults {
			fmt.Printf("  %s\n", result)
		}
	}

	// 统计匹配成功率
	totalRequests := 0
	correctMatches := 0

	for _, connResults := range results {
		for _, result := range connResults {
			if len(result) > 4 && (strings.HasPrefix(result, "✅") || strings.HasPrefix(result, "❌")) {
				totalRequests++
				if strings.HasPrefix(result, "✅") {
					correctMatches++
				}
			}
		}
	}

	fmt.Printf("\n=== 统计结果 ===\n")
	fmt.Printf("总请求数: %d\n", totalRequests)
	fmt.Printf("正确匹配: %d\n", correctMatches)
	fmt.Printf("匹配成功率: %.2f%%\n", float64(correctMatches)/float64(totalRequests)*100)

	if correctMatches == totalRequests {
		fmt.Println("🎉 所有请求响应都正确匹配！修复成功！")
	} else {
		fmt.Println("⚠️ 仍有请求响应匹配错误")
	}
}
