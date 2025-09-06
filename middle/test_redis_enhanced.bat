@echo off
REM Redis增强解析器测试脚本 (Windows版本)

echo 🚀 Redis增强解析器测试
echo ==============================

REM 检查是否有Go环境
go version >nul 2>&1
if errorlevel 1 (
    echo ❌ 未找到Go环境，请先安装Go
    exit /b 1
)

echo ✅ Go环境检查通过

REM 编译示例程序
echo 🔨 编译Redis增强解析器示例...
cd /d "%~dp0"
go build -o redis_enhanced_example.exe examples\redis_enhanced_example.go

if errorlevel 1 (
    echo ❌ 编译失败
    exit /b 1
)

echo ✅ 编译成功

REM 运行示例
echo 📋 运行Redis增强解析器示例...
echo ==============================
redis_enhanced_example.exe

REM 清理
del redis_enhanced_example.exe

echo.
echo ✅ 测试完成！
echo.
echo 📋 功能验证列表：
echo   ✓ 请求响应关联
echo   ✓ 数据库跟踪
echo   ✓ 内容截断 (最大64字符)
echo   ✓ 耗时统计
echo   ✓ 错误处理
echo.
echo 💡 在实际环境中使用：
echo   1. 确保有Redis服务器运行
echo   2. 以管理员权限运行监控器
echo   3. 指定正确的网络接口

pause