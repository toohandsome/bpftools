.PHONY: build clean run

# 编译目标
build: clean
	@echo "下载依赖..."
	go mod tidy
	@echo "生成eBPF代码..."
	go generate ./...
	@echo "移除C文件避免编译冲突..."
	mv syscall_tracer.c syscall_tracer.c.tmp
	@echo "编译Go程序..."
	go build -o syscalltracer . || (mv syscall_tracer.c.tmp syscall_tracer.c && exit 1)
	@echo "恢复C文件..."
	mv syscall_tracer.c.tmp syscall_tracer.c

# 清理
clean:
	rm -f syscalltracer
	rm -f syscalltracer_bpfel.go
	rm -f syscalltracer_bpfel.o
	rm -f syscalltracer_bpfeb.go
	rm -f syscalltracer_bpfeb.o
	rm -f syscall_tracer_bpfel.go
	rm -f syscall_tracer_bpfel.o
	# 恢复C文件如果被重命名
	mv syscall_tracer.c.tmp syscall_tracer.c 2>/dev/null || true

# 运行程序
run: build
	@echo "运行syscall tracer (需要root权限)..."
	sudo ./syscalltracer

# 检查PID是否存在
check-pid:
	@if ps -p 750849 > /dev/null 2>&1; then \
		echo "PID 750849 存在"; \
		ps -p 750849 -o pid,comm,cmd; \
	else \
		echo "PID 750849 不存在，请检查Elasticsearch进程"; \
		echo "使用以下命令查找ES进程:"; \
		echo "ps aux | grep elasticsearch"; \
	fi

# 快速调试 - 生成代码并查看类型名
quick-debug:
	go generate ./...
	grep -n "type.*Objects" syscalltracer_bpfel.go | head -3
	grep -n "func Load" syscalltracer_bpfel.go | head -3