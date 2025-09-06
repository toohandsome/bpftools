// Package config 提供中间件监控的配置管理
package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// Config 监控配置
type Config struct {
	Interface  string        `toml:"interface"`   // 网络接口名称
	Host       string        `toml:"host"`        // 默认主机地址
	Mode       string        `toml:"mode"`        // 监控模式: client, server, auto
	Filter     string        `toml:"filter"`      // 自定义BPF过滤器
	Verbose    bool          `toml:"verbose"`     // 详细输出
	Timeout    time.Duration `toml:"timeout"`     // 连接超时时间
	BufferSize int           `toml:"buffer_size"` // 包缓冲区大小
	MaxPackets int           `toml:"max_packets"` // 最大包数量

	// 多中间件配置
	Middlewares map[string]*MiddlewareConfig `toml:"middlewares"` // 中间件配置映射

	// 单中间件兼容性字段(即将废弃)
	Port       int    `toml:"port"`       // 监控端口
	Middleware string `toml:"middleware"` // 中间件类型
}

// MiddlewareConfig 单个中间件配置
type MiddlewareConfig struct {
	Type    string `toml:"type"`    // 中间件类型
	Host    string `toml:"host"`    // 主机地址
	Port    int    `toml:"port"`    // 端口
	Enabled bool   `toml:"enabled"` // 是否启用

	// Redis专用配置
	Username     string `toml:"username"`       // Redis用户名 (Redis 6.0+)
	Password     string `toml:"password"`       // Redis密码
	Database     int    `toml:"database"`       // 默认数据库编号
	RedisCliPath string `toml:"redis_cli_path"` // redis-cli可执行文件路径

	// 其他中间件的专用配置可以在这里扩展
	// PostgreSQL配置
	// SQLServer配置
	// 等等...
}

// TOMLConfig TOML配置文件结构
type TOMLConfig struct {
	Redis     *TOMLConfigItem `toml:"redis"`
	Postgres  *TOMLConfigItem `toml:"postgres"`
	SQLServer *TOMLConfigItem `toml:"sqlserver"`
	Minio     *TOMLConfigItem `toml:"minio"`
	RocketMQ  *TOMLConfigItem `toml:"rocketmq"`
}

// TOMLConfigItem TOML配置项（用于解析时间字符串）
type TOMLConfigItem struct {
	Interface  string `toml:"interface"`
	Host       string `toml:"host"`
	Port       int    `toml:"port"`
	Middleware string `toml:"middleware"`
	Mode       string `toml:"mode"`
	Filter     string `toml:"filter"`
	Verbose    bool   `toml:"verbose"`
	Timeout    string `toml:"timeout"` // TOML中作为字符串读取
	BufferSize int    `toml:"buffer_size"`
	MaxPackets int    `toml:"max_packets"`
}

// MiddlewarePort 默认端口映射
var MiddlewarePort = map[string]int{
	"redis":     6379,
	"postgres":  5432,
	"sqlserver": 1433,
	"minio":     9000,
	"rocketmq":  10911, // nameserver端口，broker默认10909
}

// GetDefaultPort 获取中间件的默认端口
func GetDefaultPort(middleware string) int {
	if port, exists := MiddlewarePort[middleware]; exists {
		return port
	}
	return 0
}

// SetDefaults 设置默认值
func (c *Config) SetDefaults() {
	if c.Host == "" {
		c.Host = "127.0.0.1" // 默认本地地址
	}
	if c.BufferSize == 0 {
		c.BufferSize = 32 * 1024 * 1024 // 32MB
	}
	if c.MaxPackets == 0 {
		c.MaxPackets = 1000
	}
	if c.Timeout == 0 {
		c.Timeout = 30 * time.Second
	}
	if c.Mode == "" {
		c.Mode = "auto"
	}

	// 初始化中间件配置映射
	if c.Middlewares == nil {
		c.Middlewares = make(map[string]*MiddlewareConfig)
	}

	// 兼容性处理：如果使用了旧的单中间件配置，转换为新格式
	if c.Middleware != "" && c.Port != 0 {
		c.Middlewares[c.Middleware] = &MiddlewareConfig{
			Type:    c.Middleware,
			Host:    c.Host,
			Port:    c.Port,
			Enabled: true,
		}
	}
}

// GetEnabledMiddlewares 获取启用的中间件配置
func (c *Config) GetEnabledMiddlewares() map[string]*MiddlewareConfig {
	enabled := make(map[string]*MiddlewareConfig)
	for name, mw := range c.Middlewares {
		if mw.Enabled {
			enabled[name] = mw
		}
	}
	return enabled
}

// AddMiddleware 添加中间件配置
func (c *Config) AddMiddleware(name string, mwConfig *MiddlewareConfig) {
	if c.Middlewares == nil {
		c.Middlewares = make(map[string]*MiddlewareConfig)
	}
	c.Middlewares[name] = mwConfig
}

// HasMiddleware 检查是否配置了指定中间件
func (c *Config) HasMiddleware(name string) bool {
	mw, exists := c.Middlewares[name]
	return exists && mw.Enabled
}

// GetAllPorts 获取所有启用中间件的端口
func (c *Config) GetAllPorts() []int {
	ports := make([]int, 0)
	portSet := make(map[int]bool)

	for _, mw := range c.GetEnabledMiddlewares() {
		if !portSet[mw.Port] {
			ports = append(ports, mw.Port)
			portSet[mw.Port] = true
		}
	}

	return ports
}

// BuildBPFFilter 构建BPF过滤器
func (c *Config) BuildBPFFilter() string {
	if c.Filter != "" {
		return c.Filter
	}

	// 获取所有端口
	ports := c.GetAllPorts()
	if len(ports) == 0 {
		// 兼容性处理：如果没有配置中间件，使用旧的Port字段
		if c.Port != 0 {
			return fmt.Sprintf("tcp and (dst port %d or src port %d)", c.Port, c.Port)
		}
		return "tcp" // 默认捕获所有TCP流量
	}

	// 构建多端口过滤器
	if len(ports) == 1 {
		// 单端口的情况
		port := ports[0]
		return fmt.Sprintf("tcp and (dst port %d or src port %d)", port, port)
	}

	// 多端口的情况，构建 OR 条件
	var conditions []string
	for _, port := range ports {
		conditions = append(conditions, fmt.Sprintf("port %d", port))
	}

	return fmt.Sprintf("tcp and (%s)", strings.Join(conditions, " or "))
}

// LoadMultiMiddlewareConfig 从文件加载多中间件配置
func LoadMultiMiddlewareConfig(configPath string) (*Config, error) {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("配置文件不存在: %s", configPath)
	}

	// 直接解析为Config结构
	var config Config
	if _, err := toml.DecodeFile(configPath, &config); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %v", err)
	}

	// 设置默认值
	config.SetDefaults()

	// 为每个中间件设置默认主机地址（如果未设置）
	for name, mw := range config.Middlewares {
		if mw.Host == "" {
			mw.Host = config.Host // 使用全局主机地址
		}
		if mw.Type == "" {
			mw.Type = name // 如果未设置类型，使用名称作为类型
		}
	}

	return &config, nil
}

// EnableMiddlewares 启用指定的中间件列表
func (c *Config) EnableMiddlewares(middlewaresList []string) {
	// 先禁用所有中间件
	for _, mw := range c.Middlewares {
		mw.Enabled = false
	}

	// 启用指定的中间件
	for _, name := range middlewaresList {
		name = strings.TrimSpace(name)
		if mw, exists := c.Middlewares[name]; exists {
			mw.Enabled = true
		} else {
			// 如果配置中不存在，创建默认配置
			defaultPort := GetDefaultPort(name)
			if defaultPort > 0 {
				c.Middlewares[name] = &MiddlewareConfig{
					Type:    name,
					Host:    c.Host,
					Port:    defaultPort,
					Enabled: true,
				}
			}
		}
	}
}

// LoadConfigFromFile 从文件加载配置
func LoadConfigFromFile(configPath, middleware string) (*Config, error) {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("配置文件不存在: %s", configPath)
	}

	var tomlConfig TOMLConfig
	if _, err := toml.DecodeFile(configPath, &tomlConfig); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %v", err)
	}

	// 根据中间件类型选择配置
	var tomlItem *TOMLConfigItem
	switch middleware {
	case "redis":
		tomlItem = tomlConfig.Redis
	case "postgres":
		tomlItem = tomlConfig.Postgres
	case "sqlserver":
		tomlItem = tomlConfig.SQLServer
	case "minio":
		tomlItem = tomlConfig.Minio
	case "rocketmq":
		tomlItem = tomlConfig.RocketMQ
	default:
		return nil, fmt.Errorf("不支持的中间件类型: %s", middleware)
	}

	if tomlItem == nil {
		return &Config{}, nil // 返回空配置，使用默认值
	}

	// 转换为Config结构
	config := &Config{
		Interface:  tomlItem.Interface,
		Host:       tomlItem.Host,
		Port:       tomlItem.Port,
		Middleware: tomlItem.Middleware,
		Mode:       tomlItem.Mode,
		Filter:     tomlItem.Filter,
		Verbose:    tomlItem.Verbose,
		BufferSize: tomlItem.BufferSize,
		MaxPackets: tomlItem.MaxPackets,
	}

	// 解析超时时间
	if tomlItem.Timeout != "" {
		timeout, err := time.ParseDuration(tomlItem.Timeout)
		if err != nil {
			return nil, fmt.Errorf("无效的超时格式: %s", tomlItem.Timeout)
		}
		config.Timeout = timeout
	}

	// 设置中间件类型（确保与请求的类型一致）
	config.Middleware = middleware

	return config, nil
}

// MergeWithCmdLineArgs 合并命令行参数（命令行优先）
func (c *Config) MergeWithCmdLineArgs(cmdConfig *Config) {
	// 命令行参数优先级最高，只有当命令行参数为默认值时才使用配置文件的值
	if cmdConfig.Interface != "" {
		c.Interface = cmdConfig.Interface
	}
	if cmdConfig.Host != "" && cmdConfig.Host != "127.0.0.1" { // 非默认值
		c.Host = cmdConfig.Host
	}
	if cmdConfig.Port != 0 {
		c.Port = cmdConfig.Port
	}
	if cmdConfig.Middleware != "" {
		c.Middleware = cmdConfig.Middleware
	}
	if cmdConfig.Mode != "" && cmdConfig.Mode != "auto" { // 非默认值
		c.Mode = cmdConfig.Mode
	}
	if cmdConfig.Filter != "" {
		c.Filter = cmdConfig.Filter
	}
	// Verbose: 命令行设置为true时优先
	if cmdConfig.Verbose {
		c.Verbose = cmdConfig.Verbose
	}
	if cmdConfig.Timeout != 0 && cmdConfig.Timeout != 30*time.Second { // 非默认值
		c.Timeout = cmdConfig.Timeout
	}
	if cmdConfig.BufferSize != 0 {
		c.BufferSize = cmdConfig.BufferSize
	}
	if cmdConfig.MaxPackets != 0 {
		c.MaxPackets = cmdConfig.MaxPackets
	}
}
