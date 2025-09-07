package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/myserver/go-server/ebpf/middle/config"
	"github.com/myserver/go-server/ebpf/middle/monitor"
)

func main() {
	var (
		configFile  = flag.String("config", "", "配置文件路径 (默认自动寻找 config-multi.toml 或 config.toml)")
		iface       = flag.String("interface", "", "网络接口名称 (如: eth0, wlan0)")
		host        = flag.String("host", "127.0.0.1", "默认主机地址")
		port        = flag.Int("port", 0, "监控端口号(兼容性)")
		middleware  = flag.String("middleware", "", "中间件类型(兼容性) (redis,postgres,sqlserver,minio,rocketmq)")
		middlewares = flag.String("middlewares", "", "启用的中间件列表(逗号分隔): redis,postgres")
		mode        = flag.String("mode", "auto", "监控模式: client(客户端), server(服务端), auto(自动检测)")
		filter      = flag.String("filter", "", "自定义BPF过滤器")
		verbose     = flag.Bool("verbose", false, "详细输出")
		timeout     = flag.Duration("timeout", 30*time.Second, "连接超时时间")
	)
	flag.Parse()

	// 创建命令行配置
	cmdConfig := &config.Config{
		Interface:  *iface,
		Host:       *host,
		Port:       *port,
		Middleware: strings.ToLower(*middleware),
		Mode:       strings.ToLower(*mode),
		Filter:     *filter,
		Verbose:    *verbose,
		Timeout:    *timeout,
	}

	// 尝试从配置文件加载配置
	var cfg *config.Config
	fileConfig, configFound, err := loadConfigWithFallback(*configFile)
	if err != nil {
		// 配置文件加载失败，使用默认配置
		if *verbose {
			// log.Printf("⚠️ 加载配置文件失败: %v，使用默认配置", err)
		}
		cfg = &config.Config{}
	} else {
		cfg = fileConfig
		if *verbose {
			fmt.Printf("✅ 成功加载配置文件: %s\n", configFound)
		}
	}

	// 处理命令行指定的中间件列表
	if *middlewares != "" {
		processMiddlewaresFlag(cfg, *middlewares)
	}

	// 合并命令行参数（命令行优先）
	cfg.MergeWithCmdLineArgs(cmdConfig)

	// 设置默认值
	cfg.SetDefaults()
	// 打印出读取的配置
	if *verbose {
		fmt.Printf("🔍 配置详细信息:\n")
		fmt.Printf("  原始配置文件配置:\n")
		fmt.Printf("    Interface: %s\n", cfg.Interface)
		fmt.Printf("    Host: %s\n", cfg.Host)
		fmt.Printf("    Mode: %s\n", cfg.Mode)
		fmt.Printf("    Verbose: %t\n", cfg.Verbose)
		fmt.Printf("    Timeout: %v\n", cfg.Timeout)
		fmt.Printf("    BufferSize: %d\n", cfg.BufferSize)
		fmt.Printf("    MaxPackets: %d\n", cfg.MaxPackets)
		fmt.Printf("    Filter: %s\n", cfg.Filter)

		fmt.Printf("  命令行参数配置:\n")
		fmt.Printf("    Interface: %s\n", cmdConfig.Interface)
		fmt.Printf("    Host: %s\n", cmdConfig.Host)
		fmt.Printf("    Port: %d\n", cmdConfig.Port)
		fmt.Printf("    Middleware: %s\n", cmdConfig.Middleware)
		fmt.Printf("    Mode: %s\n", cmdConfig.Mode)
		fmt.Printf("    Verbose: %t\n", cmdConfig.Verbose)
		fmt.Printf("    Timeout: %v\n", cmdConfig.Timeout)
		fmt.Printf("    Filter: %s\n", cmdConfig.Filter)

		fmt.Printf("  中间件配置:\n")
		for name, mw := range cfg.Middlewares {
			fmt.Printf("    %s: Type=%s, Host=%s, Port=%d, Enabled=%t\n",
				name, mw.Type, mw.Host, mw.Port, mw.Enabled)
		}

		fmt.Printf("  兼容性配置:\n")
		fmt.Printf("    Port: %d\n", cfg.Port)
		fmt.Printf("    Middleware: %s\n", cfg.Middleware)
		fmt.Println()
	}

	if *iface == "" && cfg.Interface == "" {
		fmt.Println("使用方法:")
		fmt.Println("  -config string       配置文件路径 (默认自动寻找 config-multi.toml 或 config.toml)")
		fmt.Println("  -interface string    网络接口名称 (必需)")
		fmt.Println("  -host string         默认主机地址 (默认: 127.0.0.1)")
		fmt.Println("  -middlewares string  启用的中间件列表(逗号分隔): redis,postgres,minio")
		fmt.Println("  -mode string         监控模式: client,server,auto (默认: auto)")
		fmt.Println("  -filter string       自定义BPF过滤器")
		fmt.Println("  -verbose             详细输出")
		fmt.Println("  -timeout duration    连接超时时间 (默认: 30s)")
		fmt.Println()
		fmt.Println("兼容性参数(即将废弃):")
		fmt.Println("  -port int            监控端口号")
		fmt.Println("  -middleware string   单中间件类型")
		fmt.Println()
		fmt.Println("示例:")
		fmt.Println("  # 使用默认配置文件监控多中间件")
		fmt.Println("  sudo go run main.go -interface eth0")
		fmt.Println("  # 指定配置文件")
		fmt.Println("  sudo go run main.go -interface eth0 -config config-multi.toml")
		fmt.Println("  # 命令行指定启用的中间件")
		fmt.Println("  sudo go run main.go -interface eth0 -middlewares redis,postgres")
		fmt.Println("  # 兼容性：单中间件模式")
		fmt.Println("  sudo go run main.go -interface eth0 -port 6379 -middleware redis")
		fmt.Println()
		fmt.Println("注意: 程序会按以下顺序查找配置文件:")
		fmt.Println("  1. -config 指定的文件")
		fmt.Println("  2. 当前目录下的 config-multi.toml")
		fmt.Println("  3. 当前目录下的 config.toml")
		os.Exit(1)
	}

	// 验证至少有一个中间件被启用
	enabled := cfg.GetEnabledMiddlewares()
	if len(enabled) == 0 && cfg.Port == 0 {
		log.Fatal("必须启用至少一个中间件或指定端口")
	}

	// 验证中间件类型（支持多中间件）
	validMiddlewares := []string{"redis", "postgres", "sqlserver", "minio", "rocketmq"}

	// 检查启用的中间件是否都支持
	for name, mw := range enabled {
		middlewareValid := false
		for _, validMw := range validMiddlewares {
			if strings.ToLower(mw.Type) == validMw {
				middlewareValid = true
				break
			}
		}
		if !middlewareValid {
			log.Fatalf("不支持的中间件类型 [%s]: %s. 支持的类型: %s", name, mw.Type, strings.Join(validMiddlewares, ", "))
		}
	}

	// 兼容性检查：单中间件模式
	if cfg.Middleware != "" {
		middlewareValid := false
		for _, mw := range validMiddlewares {
			if strings.ToLower(cfg.Middleware) == mw {
				middlewareValid = true
				break
			}
		}
		if !middlewareValid {
			log.Fatalf("不支持的中间件类型: %s. 支持的类型: %s", cfg.Middleware, strings.Join(validMiddlewares, ", "))
		}
	}

	// 显示最终配置信息
	fmt.Printf("启动中间件监控器...\n")
	fmt.Printf("配置文件: %s\n", configFound)
	fmt.Printf("接口: %s\n", cfg.Interface)
	fmt.Printf("主机: %s\n", cfg.Host)
	fmt.Printf("模式: %s\n", cfg.Mode)

	// 显示启用的中间件
	enabledMws := cfg.GetEnabledMiddlewares()
	if len(enabledMws) > 0 {
		fmt.Printf("启用的中间件:\n")
		for name, mw := range enabledMws {
			fmt.Printf("  - %s: %s:%d\n", name, mw.Host, mw.Port)
		}
	} else if cfg.Port != 0 {
		// 兼容性：显示旧配置
		fmt.Printf("端口: %d\n", cfg.Port)
		fmt.Printf("中间件: %s\n", cfg.Middleware)
	}

	if cfg.Verbose {
		fmt.Printf("📝 详细配置信息:\n")
		fmt.Printf("  过滤器: %s\n", cfg.Filter)
		fmt.Printf("  超时: %v\n", cfg.Timeout)
		fmt.Printf("  缓冲区: %d\n", cfg.BufferSize)
		fmt.Printf("  最大包数: %d\n", cfg.MaxPackets)
	}

	// 创建上下文
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 信号处理
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// 创建监控器
	mon, err := monitor.NewMonitor(cfg)
	if err != nil {
		log.Fatalf("创建监控器失败: %v", err)
	}

	// 启动监控器 - 在独立的goroutine中运行
	monitorDone := make(chan error, 1)
	go func() {
		monitorDone <- mon.Start(ctx)
	}()

	fmt.Println("监控已启动，按 Ctrl+C 停止...")

	// 等待信号或监控完成
	select {
	case sig := <-sigChan:
		fmt.Printf("\n接收到停止信号 %v，正在停止监控...\n", sig)

		// 创建超时上下文，确保在合理时间内停止
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer stopCancel()

		// 在独立的goroutine中执行停止操作
		stopDone := make(chan struct{})
		go func() {
			defer close(stopDone)
			cancel()   // 取消上下文
			mon.Stop() // 停止监控器
		}()

		// 等待停止完成或超时
		select {
		case <-stopDone:
			fmt.Println("监控已正常停止")
		case <-stopCtx.Done():
			fmt.Println("停止超时，强制退出")
			os.Exit(1)
		}

	case err := <-monitorDone:
		if err != nil && err != context.Canceled {
			// log.Printf("监控器错误: %v", err)
		}
		cancel()
		mon.Stop()
	}

	fmt.Println("监控已停止")
}

// loadConfigWithFallback 根据优先级加载配置文件
func loadConfigWithFallback(specifiedConfig string) (*config.Config, string, error) {
	// 如果用户指定了配置文件，直接使用
	if specifiedConfig != "" {
		cfg, err := loadConfigFromFile(specifiedConfig)
		return cfg, specifiedConfig, err
	}

	// 按优先级寻找默认配置文件
	configFiles := []string{
		"config-multi.toml", // 新的多中间件配置文件
		"config.toml",       // 原有的配置文件(兼容性)
	}

	for _, configFile := range configFiles {
		if _, err := os.Stat(configFile); err == nil {
			cfg, err := loadConfigFromFile(configFile)
			return cfg, configFile, err
		}
	}

	// 没有找到任何配置文件
	return nil, "", fmt.Errorf("未找到配置文件: %s", strings.Join(configFiles, ", "))
}

// loadConfigFromFile 加载配置文件（支持多中间件格式）
func loadConfigFromFile(configPath string) (*config.Config, error) {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("配置文件不存在: %s", configPath)
	}

	// 使用配置包的加载函数，确保正确处理继承逻辑
	return config.LoadMultiMiddlewareConfig(configPath)
}

// processMiddlewaresFlag 处理命令行指定的中间件列表
func processMiddlewaresFlag(cfg *config.Config, middlewaresList string) {
	middlewareNames := strings.Split(middlewaresList, ",")

	// 先禁用所有中间件
	for name, mw := range cfg.Middlewares {
		mw.Enabled = false
		cfg.Middlewares[name] = mw
	}

	// 启用指定的中间件
	for _, name := range middlewareNames {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}

		// 检查是否已配置
		if mw, exists := cfg.Middlewares[name]; exists {
			mw.Enabled = true
			cfg.Middlewares[name] = mw
		} else {
			// 使用默认配置创建
			defaultPort := config.GetDefaultPort(name)
			if defaultPort > 0 {
				cfg.AddMiddleware(name, &config.MiddlewareConfig{
					Type:    name,
					Host:    cfg.Host,
					Port:    defaultPort,
					Enabled: true,
				})
			}
		}
	}
}
