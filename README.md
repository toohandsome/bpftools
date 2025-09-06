# eBPF HTTP 监控程序

## 项目简介

这是一个使用Go语言实现的eBPF程序，用于监控指定程序接收到的和发出的HTTP请求，并实时打印出具体的请求头和请求体信息。

## 功能特性

- 使用eBPF技术进行高性能网络监控
- 支持监控指定进程的HTTP请求
- 实时显示HTTP请求头和请求体
- 支持过滤不同的HTTP方法
- 低开销，对目标程序影响极小

## 系统要求

- Linux内核版本 >= 4.18 (推荐 5.8+)
- Go 1.18+
- 管理员权限（root）

## 编译依赖

- clang
- llvm
- linux-headers
- libbpf-dev

## 使用方法

```bash
# 编译程序
make build

# 监控指定PID的HTTP请求
sudo ./http-monitor -pid 12345

# 监控指定程序名的HTTP请求
sudo ./http-monitor -name nginx

# 显示所有选项
./http-monitor -help
```

## 项目结构

```
ebpf/
├── README.md                 # 项目说明文档
├── Makefile                  # 编译配置文件
├── go.mod                    # Go模块文件
├── cmd/
│   └── main.go               # 主程序入口
├── internal/
│   ├── ebpf/
│   │   ├── http_monitor.c    # eBPF内核程序
│   │   └── http_monitor.go   # eBPF程序加载器
│   ├── parser/
│   │   └── http.go           # HTTP协议解析器
│   └── monitor/
│       └── process.go        # 进程监控逻辑
└── scripts/
    └── setup.sh              # 环境配置脚本
```

## 注意事项

1. 需要root权限运行
2. 确保系统支持eBPF功能
3. 监控HTTPS流量需要额外配置
4. 建议在测试环境先验证功能