package main

import (
	"context"
	"fmt"
	"sync"

	"github.com/redis/go-redis/v9"
)

func main() {
	// 创建 Redis 客户端
	rdb := redis.NewClient(&redis.Options{
		Addr:     "192.168.2.226:6379", // Redis 服务器地址
		Password: "",                   // 无密码
		DB:       0,                    // 使用默认数据库
	})

	ctx := context.Background()

	// 测试连接
	if err := rdb.Ping(ctx).Err(); err != nil {
		panic(fmt.Sprintf("无法连接到 Redis: %v", err))
	}

	// 要操作的键值对
	keys := []string{"a1", "b1", "c1", "d1", "e1", "f1", "g1", "h1", "i1", "j1",
		"k1", "l1", "m1", "n1", "o1", "p1", "q1", "r1", "s1", "t1",
		"u1", "v1", "w1", "x1", "y1", "z1"}

	values := []string{"aaaaaaa", "bbbbbbb", "ccccccc", "ddddddd", "eeeeeee", "fffffff", "ggggggg", "hhhhhhh", "iiiiiii", "jjjjjjj",
		"kkkkkkk", "lllllll", "mmmmmmm", "nnnnnnn", "ooooooo", "ppppppp", "qqqqqqq", "rrrrrrr", "sssssss", "ttttttt",
		"uuuuuuu", "vvvvvvv", "wwwwwww", "xxxxxxx", "yyyyyyy", "zzzzzzz"}

	var wg sync.WaitGroup

	// 并发执行 SET 操作
	fmt.Println("开始并发 SET 操作...")
	for i, key := range keys {
		wg.Add(1)
		go func(k string, v string) {
			defer wg.Done()
			err := rdb.Set(ctx, k, v, 0).Err()
			if err != nil {
				fmt.Printf("SET %s 失败: %v\n", k, err)
			} else {
				fmt.Printf("SET %s = %s 成功\n", k, v)
			}
		}(key, values[i])
	}
	wg.Wait()

	// 并发执行 GET 操作
	fmt.Println("\n开始并发 GET 操作...")
	for _, key := range keys {
		wg.Add(1)
		go func(k string) {
			defer wg.Done()
			val, err := rdb.Get(ctx, k).Result()
			if err != nil {
				fmt.Printf("GET %s 失败: %v\n", k, err)
			} else {
				fmt.Printf("GET %s = %s\n", k, val)
			}
		}(key)
	}
	wg.Wait()

	fmt.Println("\n所有操作完成！")
}
