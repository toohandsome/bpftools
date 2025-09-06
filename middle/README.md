# 中间件流量监控工具

一个基于 GoPacket 的高性能中间件流量监控工具，支持监控 Redis、PostgreSQL、SQL Server、MinIO/S3、RocketMQ 等中间件的请求响应流量，提供实时的性能统计和延迟分析。

## 支持的中间件

- **Redis** - RESP 协议解析
- **PostgreSQL** - Wire Protocol 协议解析  
- **SQL Server** - TDS 协议解析
- **MinIO/S3** - HTTP/REST API 协议解析
- **RocketMQ** - 自定义协议解析

## 功能特性

- 🚀 **高性能监控** - 基于 GoPacket 的高效包捕获
- 📊 **实时统计** - QPS、延迟、成功率等实时统计
- 🔍 **协议解析** - 深度解析各种中间件协议
- 📈 **性能分析** - 请求响应匹配和耗时分析
- 🎯 **智能识别** - 自动识别请求和响应
- 🌐 **双向监控** - 支持客户端和服务端监控模式

## 编译和运行

### 前提条件

确保您的系统已安装：
- Go 1.18+
- libpcap-dev (Linux) 或 WinPcap/Npcap (Windows)
- 管理员/root 权限（网络包捕获需要）

### 编译

```bash
cd middle
go build -o middleware-monitor main.go
```

### 使用方法

```bash
# 基本用法
sudo ./middleware-monitor -interface eth0 -port 6379 -middleware redis

# 监控 PostgreSQL
sudo ./middleware-monitor -interface eth0 -port 5432 -middleware postgres -mode server

# 监控 MinIO S3 API
sudo ./middleware-monitor -interface eth0 -port 9000 -middleware minio -verbose

# 监控 RocketMQ
sudo ./middleware-monitor -interface wlan0 -port 10911 -middleware rocketmq -timeout 60s
```

### 参数说明

- `-interface` - 网络接口名称（必需）
- `-port` - 监控端口号（必需）  
- `-middleware` - 中间件类型（必需）：redis, postgres, sqlserver, minio, rocketmq
- `-mode` - 监控模式：client（客户端）, server（服务端）, auto（自动检测，默认）
- `-filter` - 自定义 BPF 过滤器
- `-verbose` - 详细输出
- `-timeout` - 连接超时时间（默认 30s）

## 监控模式

### 客户端模式 (Client)
在运行客户端应用的服务器上部署，监控：
- 客户端发出的请求
- 服务端返回的响应
- 客户端视角的延迟统计

### 服务端模式 (Server)  
在运行中间件服务的服务器上部署，监控：
- 接收到的客户端请求
- 发出的服务端响应  
- 服务端视角的处理统计

### 自动模式 (Auto)
自动检测流量方向，同时监控入站和出站流量

## 输出示例

```
启动中间件监控器...
接口: eth0
端口: 6379
中间件: redis
模式: auto
监控已启动，按 Ctrl+C 停止...

[redis] GET:key_1234 -> SimpleString (耗时: 1.2ms, 成功: true)
[redis] SET:user:1001 -> SimpleString (耗时: 0.8ms, 成功: true)
[redis] MGET:batch_query -> Array (耗时: 2.1ms, 成功: true)

=== 中间件监控统计 ===
运行时间: 1m23s
总请求数: 1542
总响应数: 1540
成功数量: 1535
错误数量: 5
成功率: 99.68%
平均延迟: 1.8ms
最小延迟: 0.3ms
最大延迟: 15.2ms
发送字节: 156.2 KB
接收字节: 89.7 KB
平均QPS: 18.6
==================
```

## 协议支持详情

### Redis (RESP协议)
- 支持所有 Redis 命令
- 解析 RESP 格式的请求和响应
- 识别批量字符串、数组、错误等类型

### PostgreSQL (Wire Protocol)  
- 支持 Query、Parse、Bind、Execute 等消息
- 解析启动消息、认证流程
- 识别错误响应和状态信息

### SQL Server (TDS协议)
- 支持 SQL 批处理、RPC 调用
- 解析 Login7、PreLogin 消息
- 识别表格响应和错误信息

### MinIO/S3 (HTTP API)
- 支持所有 S3 API 操作
- 解析 GET、PUT、DELETE 等操作
- 识别分片上传、ACL 等高级功能

### RocketMQ (自定义协议)
- 支持消息发送、拉取、查询
- 解析心跳、注册、事务消息
- 识别 NameServer 和 Broker 通信

## 性能考虑

- 使用高效的包捕获机制，对目标应用影响极小
- 支持 BPF 过滤器，减少不必要的包处理
- 内存池复用，避免频繁的内存分配
- 可配置的缓冲区大小和超时时间

## 故障排除

### 权限问题
```bash
# 确保有足够的权限捕获网络包
sudo setcap cap_net_raw,cap_net_admin=eip ./middleware-monitor
```

### 网络接口
```bash
# 查看可用的网络接口
ip addr show
# 或
ifconfig
```

### 包捕获测试
```bash
# 测试基本的包捕获功能
sudo tcpdump -i eth0 -c 10
```

## 扩展开发

添加新的中间件协议支持：

1. 在 `parsers/` 目录创建新的解析器
2. 实现 `ProtocolParser` 接口
3. 在 `parsers/parser.go` 中注册新解析器
4. 更新配置和文档

```go
// 示例：添加 MySQL 协议支持
type MySQLParser struct{}

func (p *MySQLParser) ParseRequest(data []byte) (*types.Message, error) {
    // 实现 MySQL 协议解析
}

func (p *MySQLParser) IsRequest(data []byte) bool {
    // 判断是否为 MySQL 请求
}
```

## 许可证

MIT License

## 贡献

欢迎提交 Issue 和 Pull Request！