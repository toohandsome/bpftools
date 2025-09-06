# Makefile for Middleware Monitor

BINARY_NAME=middleware-monitor
GO_FILES=$(shell find . -name "*.go" -type f)
BUILD_DIR=build
INSTALL_DIR=/usr/local/bin

# 版本信息
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u '+%Y-%m-%d %H:%M:%S UTC')
LDFLAGS=-ldflags "-X 'main.Version=$(VERSION)' -X 'main.BuildTime=$(BUILD_TIME)'"

.PHONY: all build clean test install uninstall deps check fmt vet

# 默认目标
all: build

# 编译
build: $(BUILD_DIR)/$(BINARY_NAME)

$(BUILD_DIR)/$(BINARY_NAME): $(GO_FILES)
	@mkdir -p $(BUILD_DIR)
	@echo "编译 $(BINARY_NAME)..."
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) main.go
	@echo "编译完成: $(BUILD_DIR)/$(BINARY_NAME)"

# 交叉编译
build-linux:
	@mkdir -p $(BUILD_DIR)
	@echo "交叉编译 Linux 版本..."
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 main.go

build-windows:
	@mkdir -p $(BUILD_DIR)
	@echo "交叉编译 Windows 版本..."
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe main.go

build-darwin:
	@mkdir -p $(BUILD_DIR)
	@echo "交叉编译 macOS 版本..."
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 main.go

# 编译所有平台
build-all: build-linux build-windows build-darwin

# 清理
clean:
	@echo "清理构建文件..."
	rm -rf $(BUILD_DIR)
	go clean

# 测试
test:
	@echo "运行测试..."
	go test -v ./...

# 基准测试
bench:
	@echo "运行基准测试..."
	go test -bench=. -benchmem ./...

# 安装依赖
deps:
	@echo "安装依赖..."
	go mod tidy
	go mod download

# 代码检查
check: fmt vet
	@echo "运行 staticcheck..."
	which staticcheck >/dev/null 2>&1 || go install honnef.co/go/tools/cmd/staticcheck@latest
	staticcheck ./...

# 格式化代码
fmt:
	@echo "格式化代码..."
	go fmt ./...

# 代码检查
vet:
	@echo "运行 go vet..."
	go vet ./...

# 安装到系统
install: build
	@echo "安装 $(BINARY_NAME) 到 $(INSTALL_DIR)..."
	sudo install -m 755 $(BUILD_DIR)/$(BINARY_NAME) $(INSTALL_DIR)/
	@echo "安装完成"

# 从系统卸载
uninstall:
	@echo "卸载 $(BINARY_NAME)..."
	sudo rm -f $(INSTALL_DIR)/$(BINARY_NAME)
	@echo "卸载完成"

# 运行示例
run-redis:
	@echo "运行 Redis 监控示例..."
	sudo ./$(BUILD_DIR)/$(BINARY_NAME) -interface lo -port 6379 -middleware redis -verbose

run-postgres:
	@echo "运行 PostgreSQL 监控示例..."
	sudo ./$(BUILD_DIR)/$(BINARY_NAME) -interface lo -port 5432 -middleware postgres -verbose

run-minio:
	@echo "运行 MinIO 监控示例..."
	sudo ./$(BUILD_DIR)/$(BINARY_NAME) -interface lo -port 9000 -middleware minio -verbose

# 检查系统依赖
check-deps:
	@echo "检查系统依赖..."
	@which go >/dev/null 2>&1 || (echo "错误: 未安装 Go"; exit 1)
	@go version
	@echo "检查 libpcap..."
	@pkg-config --exists libpcap || (echo "警告: 未找到 libpcap-dev，可能需要安装"; exit 1)
	@echo "系统依赖检查通过"

# 开发模式运行
dev:
	@echo "开发模式运行..."
	go run main.go -interface lo -port 6379 -middleware redis -verbose

# 生成文档
docs:
	@echo "生成文档..."
	which godoc >/dev/null 2>&1 || go install golang.org/x/tools/cmd/godoc@latest
	@echo "启动文档服务器: http://localhost:6060"
	godoc -http=:6060

# 打包发布
package: build-all
	@echo "打包发布版本..."
	@mkdir -p $(BUILD_DIR)/release
	tar -czf $(BUILD_DIR)/release/$(BINARY_NAME)-$(VERSION)-linux-amd64.tar.gz -C $(BUILD_DIR) $(BINARY_NAME)-linux-amd64 -C .. README.md
	zip -j $(BUILD_DIR)/release/$(BINARY_NAME)-$(VERSION)-windows-amd64.zip $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe README.md
	tar -czf $(BUILD_DIR)/release/$(BINARY_NAME)-$(VERSION)-darwin-amd64.tar.gz -C $(BUILD_DIR) $(BINARY_NAME)-darwin-amd64 -C .. README.md
	@echo "打包完成: $(BUILD_DIR)/release/"

# 帮助信息
help:
	@echo "可用的目标:"
	@echo "  build         - 编译程序"
	@echo "  build-all     - 编译所有平台版本"
	@echo "  clean         - 清理构建文件"
	@echo "  test          - 运行测试"
	@echo "  bench         - 运行基准测试"
	@echo "  deps          - 安装依赖"
	@echo "  check         - 代码检查"
	@echo "  fmt           - 格式化代码"
	@echo "  vet           - 静态分析"
	@echo "  install       - 安装到系统"
	@echo "  uninstall     - 从系统卸载"
	@echo "  check-deps    - 检查系统依赖"
	@echo "  dev           - 开发模式运行"
	@echo "  docs          - 生成文档"
	@echo "  package       - 打包发布"
	@echo "  run-*         - 运行特定中间件监控示例"