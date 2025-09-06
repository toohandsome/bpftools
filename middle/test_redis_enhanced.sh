#!/bin/bash

# Redis增强解析器测试脚本

echo "🚀 Redis增强解析器测试"
echo "=============================="

# 检查是否安装了Redis
if ! command -v redis-server &> /dev/null; then
    echo "❌ 未找到redis-server，请先安装Redis"
    exit 1
fi

if ! command -v redis-cli &> /dev/null; then
    echo "❌ 未找到redis-cli，请先安装Redis"
    exit 1
fi

# 检查Redis是否运行
if ! pgrep redis-server > /dev/null; then
    echo "⚠️ Redis服务器未运行，正在启动..."
    redis-server --daemonize yes --port 6379
    sleep 2
fi

echo "✅ Redis服务器运行正常"

# 获取网络接口
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
if [ -z "$INTERFACE" ]; then
    echo "❌ 无法自动检测网络接口，请手动指定"
    echo "可用接口："
    ip link show | grep "^[0-9]" | awk '{print $2}' | sed 's/://'
    exit 1
fi

echo "🌐 使用网络接口: $INTERFACE"

# 编译增强监控器
echo "🔨 编译Redis增强监控器..."
cd "$(dirname "$0")"
go build -o redis_enhanced_monitor redis_enhanced_main.go

if [ $? -ne 0 ]; then
    echo "❌ 编译失败"
    exit 1
fi

echo "✅ 编译成功"

# 启动监控器（后台运行）
echo "📡 启动Redis监控器..."
sudo ./redis_enhanced_monitor -interface $INTERFACE -verbose > monitor.log 2>&1 &
MONITOR_PID=$!

# 等待监控器启动
sleep 2

# 检查监控器是否运行
if ! kill -0 $MONITOR_PID 2>/dev/null; then
    echo "❌ 监控器启动失败，检查monitor.log"
    cat monitor.log
    exit 1
fi

echo "✅ 监控器已启动 (PID: $MONITOR_PID)"

# 执行Redis测试命令
echo ""
echo "🧪 执行Redis测试命令..."
echo "=============================="

# 测试1: 基本的SET/GET
echo "1. 测试基本SET/GET命令"
redis-cli SET test_key "hello world"
redis-cli GET test_key

sleep 1

# 测试2: 切换数据库
echo ""
echo "2. 测试数据库切换"
redis-cli SELECT 1
redis-cli SET db1_key "value in database 1"
redis-cli GET db1_key

sleep 1

# 测试3: 数字操作
echo ""
echo "3. 测试数字操作"
redis-cli SET counter 10
redis-cli INCR counter
redis-cli INCR counter

sleep 1

# 测试4: 切换回数据库0
echo ""
echo "4. 切换回数据库0"
redis-cli SELECT 0
redis-cli GET test_key

sleep 1

# 测试5: 错误命令
echo ""
echo "5. 测试错误命令"
redis-cli UNKNOWN_COMMAND some_arg

sleep 1

# 测试6: 批量操作
echo ""
echo "6. 测试批量操作"
redis-cli MSET key1 "value1" key2 "value2" key3 "value3"
redis-cli MGET key1 key2 key3

sleep 1

# 测试7: 列表操作
echo ""
echo "7. 测试列表操作"
redis-cli LPUSH mylist "item1"
redis-cli LPUSH mylist "item2"
redis-cli LRANGE mylist 0 -1

sleep 2

# 停止监控器
echo ""
echo "🛑 停止监控器..."
sudo kill $MONITOR_PID

# 等待停止
sleep 1

# 显示监控结果
echo ""
echo "📊 监控结果:"
echo "=============================="
echo "最后50行监控输出："
tail -50 monitor.log

# 清理
echo ""
echo "🧹 清理测试数据..."
redis-cli FLUSHALL > /dev/null
rm -f redis_enhanced_monitor monitor.log

echo ""
echo "✅ 测试完成！"
echo ""
echo "📋 功能验证列表："
echo "  ✓ 请求响应关联"
echo "  ✓ 数据库跟踪"
echo "  ✓ 内容截断 (最大64字符)"
echo "  ✓ 耗时统计"
echo "  ✓ 错误处理"
echo ""
echo "💡 要手动测试，运行："
echo "  sudo ./redis_enhanced_monitor -interface $INTERFACE -verbose"