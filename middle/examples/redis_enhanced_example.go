// Package main - Redis增强解析器使用示例
package main

import (
	"fmt"
	"log"
	"time"

	"github.com/myserver/go-server/ebpf/middle/monitor"
	"github.com/myserver/go-server/ebpf/middle/types"
)

func main() {
	fmt.Println("🚀 Redis增强解析器示例")

	// 创建Redis监控器
	redisMonitor := monitor.NewRedisMonitor(true)

	// 设置回调函数
	redisMonitor.SetCallback(func(rr *types.RequestResponse) {
		log.Printf("📊 监控到请求响应对: %s -> %s (耗时: %v)",
			rr.Request.Command,
			extractResponseSummary(rr.Response),
			rr.Duration)
	})

	// 启动监控
	if err := redisMonitor.Start(); err != nil {
		log.Fatalf("启动监控失败: %v", err)
	}
	defer redisMonitor.Stop()

	// 模拟连接
	conn := &types.Connection{
		LocalAddr:  "127.0.0.1:45678",
		RemoteAddr: "127.0.0.1:6379",
		Direction:  types.DirectionOutbound,
		StartTime:  time.Now(),
	}

	// 模拟Redis协议数据包
	testRedisProtocol(redisMonitor, conn)

	// 等待一下再打印统计
	time.Sleep(100 * time.Millisecond)
	redisMonitor.PrintStats()
}

// testRedisProtocol 测试Redis协议解析
func testRedisProtocol(monitor *monitor.RedisMonitor, conn *types.Connection) {
	fmt.Println("\n📋 测试Redis协议解析...")

	// 测试用例1: SET命令
	fmt.Println("\n1. 测试SET命令")

	// SET key value 请求
	setRequest := []byte("*3\r\n$3\r\nSET\r\n$7\r\nmykey01\r\n$11\r\nhello world\r\n")
	if err := monitor.ProcessPacket(setRequest, conn); err != nil {
		log.Printf("处理SET请求失败: %v", err)
	}

	// 模拟网络延迟
	time.Sleep(2 * time.Millisecond)

	// SET响应 (OK)
	setResponse := []byte("+OK\r\n")
	if err := monitor.ProcessPacket(setResponse, conn); err != nil {
		log.Printf("处理SET响应失败: %v", err)
	}

	// 测试用例2: GET命令
	fmt.Println("\n2. 测试GET命令")

	// GET key 请求
	getRequest := []byte("*2\r\n$3\r\nGET\r\n$7\r\nmykey01\r\n")
	if err := monitor.ProcessPacket(getRequest, conn); err != nil {
		log.Printf("处理GET请求失败: %v", err)
	}

	time.Sleep(1 * time.Millisecond)

	// GET响应 (返回值)
	getResponse := []byte("$11\r\nhello world\r\n")
	if err := monitor.ProcessPacket(getResponse, conn); err != nil {
		log.Printf("处理GET响应失败: %v", err)
	}

	// 测试用例3: SELECT命令 (切换数据库)
	fmt.Println("\n3. 测试SELECT命令")

	// SELECT 1 请求
	selectRequest := []byte("*2\r\n$6\r\nSELECT\r\n$1\r\n1\r\n")
	if err := monitor.ProcessPacket(selectRequest, conn); err != nil {
		log.Printf("处理SELECT请求失败: %v", err)
	}

	time.Sleep(1 * time.Millisecond)

	// SELECT响应 (OK)
	selectResponse := []byte("+OK\r\n")
	if err := monitor.ProcessPacket(selectResponse, conn); err != nil {
		log.Printf("处理SELECT响应失败: %v", err)
	}

	// 测试用例4: 在新数据库中的操作
	fmt.Println("\n4. 测试数据库1中的操作")

	// SET another_key value 请求 (在数据库1中)
	setRequest2 := []byte("*3\r\n$3\r\nSET\r\n$11\r\nanother_key\r\n$6\r\nvalue1\r\n")
	if err := monitor.ProcessPacket(setRequest2, conn); err != nil {
		log.Printf("处理SET请求2失败: %v", err)
	}

	time.Sleep(3 * time.Millisecond)

	// SET响应 (OK)
	setResponse2 := []byte("+OK\r\n")
	if err := monitor.ProcessPacket(setResponse2, conn); err != nil {
		log.Printf("处理SET响应2失败: %v", err)
	}

	// 测试用例5: 错误响应
	fmt.Println("\n5. 测试错误响应")

	// 不存在的命令
	badRequest := []byte("*1\r\n$10\r\nBADCOMMAND\r\n")
	if err := monitor.ProcessPacket(badRequest, conn); err != nil {
		log.Printf("处理错误请求失败: %v", err)
	}

	time.Sleep(1 * time.Millisecond)

	// 错误响应
	errorResponse := []byte("-ERR unknown command 'BADCOMMAND'\r\n")
	if err := monitor.ProcessPacket(errorResponse, conn); err != nil {
		log.Printf("处理错误响应失败: %v", err)
	}

	// 测试用例6: 数字响应
	fmt.Println("\n6. 测试数字响应")

	// INCR命令
	incrRequest := []byte("*2\r\n$4\r\nINCR\r\n$7\r\ncounter\r\n")
	if err := monitor.ProcessPacket(incrRequest, conn); err != nil {
		log.Printf("处理INCR请求失败: %v", err)
	}

	time.Sleep(1 * time.Millisecond)

	// 数字响应
	incrResponse := []byte(":1\r\n")
	if err := monitor.ProcessPacket(incrResponse, conn); err != nil {
		log.Printf("处理INCR响应失败: %v", err)
	}
}

// extractResponseSummary 提取响应摘要
func extractResponseSummary(response *types.Message) string {
	if response.ParsedData != nil {
		if respStr, ok := response.ParsedData.(string); ok {
			if len(respStr) > 20 {
				return respStr[:20] + "..."
			}
			return respStr
		}
		if respInt, ok := response.ParsedData.(int64); ok {
			return fmt.Sprintf("%d", respInt)
		}
	}
	return response.Command
}
