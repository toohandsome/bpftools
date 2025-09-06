# 系统调用跟踪器 + 网络包捕获器

这个程序专门用来监控特定PID的网络相关系统调用，并通过网络包捕获来获取实际的HTTP响应数据，帮助调试HTTP响应体捕获问题。

## 功能特性

- 专门监控PID 750849 (Elasticsearch进程)
- 捕获所有网络相关的系统调用：
  - **读取操作**: read, readv
  - **写入操作**: write, writev  
  - **网络发送**: send, sendto, sendmsg
  - **文件传输**: sendfile
- **双重检测机制**：
  - eBPF系统调用监控：识别特殊系统调用（Len=0但RetVal>0）
  - 网络包捕获：直接从网络层捕获HTTP响应数据
- 显示文件描述符、数据长度和数据内容预览
- 对可能包含HTTP内容的大数据包进行完整输出
- 支持复杂系统调用（sendmsg, writev等）的监控
- **特殊系统调用检测**：自动识别使用sendfile等特殊方式发送的数据

## 使用方法

1. 首先检查目标PID是否存在：
```bash
make check-pid
```

2. 如果PID不是750849，请修改以下文件中的TARGET_PID：
   - `syscall_tracer.c` 第7行
   - `main.go` 第19行

3. 编译并运行：
```bash
make run
```

4. 或者分步执行：
```bash
make build
sudo ./syscall-tracer
```

## 输出格式

### eBPF系统调用监控：
```
[WRITE] PID=750849, Comm=elasticsearch[M, FD=226, Len=87, RetVal=87, Data="HTTP/1.1 200 OK\r\ncontent-type: application/json..."
[WRITE] PID=750849, Comm=elasticsearch[M, FD=226, Len=0, RetVal=334, Data="\x00\x00\x00..."
!!! 特殊系统调用检测 !!! PID=750849, FD=226, Len=0, RetVal=334
*** 找到目标HTTP响应！但无法直接读取数据 ***
```

### 网络包捕获：
```
=== 捕获到可能的HTTP响应包 ===
时间: 2025-08-31 11:25:21
长度: 334 字节
TCP端口: 9200 -> 12345
HTTP响应内容:
HTTP/1.1 200 OK
Content-Type: application/json
{"took":1,"timed_out":false,"_shards":{"total":1,"successful":1}...}
=== 包捕获结束 ===
```

注意：
- 对于简单的read/write/send调用，会显示实际数据内容
- 对于特殊系统调用（sendfile等），无法通过eBPF读取数据
- 网络包捕获可以获取实际网络传输的HTTP数据

## 查找响应体

重点关注：
- **WRITE操作**：特别关注write, writev, send, sendto, sendmsg, sendfile等写入操作
- **数据长度较大的包**：>100字节的数据包
- **FD号码不同的情况**：同一连接可能使用多个FD
- **包含JSON数据的包**：可能是响应体
- **系统调用类型**：不同类型的系统调用可能承载不同的数据

## 注意事项

- 需要root权限运行
- 确保目标进程正在运行
- 程序会产生大量输出，建议重定向到文件或使用grep过滤