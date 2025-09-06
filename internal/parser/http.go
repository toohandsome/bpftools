package parser

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"
)

type HTTPInfo struct {
	Direction string // request or response or unknown
	Method    string // GET, POST, etc.
	URL       string // request URL path
	Status    string // response status (e.g., "200 OK")
	Headers   map[string]string
	Body      string
}

func isLikelyHTTPStart(s string) bool {
	if len(s) == 0 {
		return false
	}
	// 仅取前 16 字节做快速检查
	prefix := s
	if len(prefix) > 16 {
		prefix = prefix[:16]
	}
	// 必须全部是可打印 ASCII（范围 32..126，另外允许 \r 和 \n 和 \t）
	for i := 0; i < len(prefix); i++ {
		c := prefix[i]
		if c == '\r' || c == '\n' || c == '\t' {
			continue
		}
		if c < 32 || c > 126 {
			return false
		}
	}
	// 必须包含空格（如: "GET / HTTP/1.1" 或 "HTTP/1.1 200 OK"）或有斜杠模式
	return strings.HasPrefix(prefix, "HTTP/") || strings.Contains(prefix, " ")
}

func ParseHTTP(payload string) HTTPInfo {
	info := HTTPInfo{Headers: map[string]string{}}

	// 首先检查是否为有效的HTTP数据
	if !isLikelyHTTPStart(payload) {
		info.Direction = "unknown"
		return info
	}

	// 尝试使用net/http标准库解析
	if httpInfo, ok := parseWithStandardLibrary(payload); ok {
		return httpInfo
	}

	// 降级到手动解析
	return parseManually(payload)
}

// parseWithStandardLibrary 使用net/http标准库解析HTTP消息
func parseWithStandardLibrary(payload string) (HTTPInfo, bool) {
	info := HTTPInfo{Headers: map[string]string{}}
	reader := strings.NewReader(payload)

	if strings.HasPrefix(payload, "HTTP/") {
		// 解析HTTP响应
		resp, err := http.ReadResponse(bufio.NewReader(reader), nil)
		if err != nil {
			return info, false
		}
		defer resp.Body.Close()

		info.Direction = "response"
		info.Status = resp.Status
		info.Headers[":start-line"] = fmt.Sprintf("HTTP/%d.%d %s", resp.ProtoMajor, resp.ProtoMinor, resp.Status)
		info.Headers[":status"] = strconv.Itoa(resp.StatusCode)

		// 复制所有响应头
		for k, v := range resp.Header {
			info.Headers[k] = strings.Join(v, ", ")
		}

		// 读取响应体
		if body, err := io.ReadAll(resp.Body); err == nil {
			info.Body = string(body)
		}

		return info, true
	} else {
		// 解析HTTP请求
		req, err := http.ReadRequest(bufio.NewReader(reader))
		if err != nil {
			return info, false
		}
		defer req.Body.Close()

		info.Direction = "request"
		info.Method = req.Method
		info.URL = req.URL.String()
		info.Headers[":start-line"] = fmt.Sprintf("%s %s HTTP/%d.%d", req.Method, req.URL.RequestURI(), req.ProtoMajor, req.ProtoMinor)
		info.Headers[":method"] = req.Method
		info.Headers[":path"] = req.URL.Path
		if req.URL.RawQuery != "" {
			info.Headers[":query"] = req.URL.RawQuery
		}

		// 复制所有请求头
		for k, v := range req.Header {
			info.Headers[k] = strings.Join(v, ", ")
		}

		// 读取请求体
		if body, err := io.ReadAll(req.Body); err == nil {
			info.Body = string(body)
		}

		return info, true
	}
}

// parseManually 手动解析HTTP消息（降级方案）
func parseManually(payload string) HTTPInfo {
	info := HTTPInfo{Headers: map[string]string{}}

	first := payload[:]
	if strings.HasPrefix(first, "HTTP/") {
		info.Direction = "response"
	} else if isHTTPMethod(first) {
		info.Direction = "request"
	} else {
		info.Direction = "unknown"
	}

	hs, body, _ := strings.Cut(payload, "\r\n\r\n")
	scanner := bufio.NewScanner(strings.NewReader(hs))
	scanner.Split(bufio.ScanLines)
	firstLine := true
	for scanner.Scan() {
		line := scanner.Text()
		// 若行中存在非ASCII，可视为噪音，直接放弃解析
		if !utf8.ValidString(line) {
			info.Direction = "unknown"
			info.Headers = map[string]string{}
			info.Body = ""
			return info
		}
		if firstLine {
			info.Headers[":start-line"] = line

			// Parse method, URL, and status from first line
			if info.Direction == "request" {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					info.Method = parts[0]
					info.URL = parts[1]
				}
			} else if info.Direction == "response" {
				// HTTP/1.1 200 OK
				if idx := strings.Index(line, " "); idx > 0 && len(line) > idx+1 {
					info.Status = strings.TrimSpace(line[idx+1:])
				}
			}

			firstLine = false
			continue
		}
		if i := strings.Index(line, ":"); i > 0 {
			k := strings.TrimSpace(line[:i])
			v := strings.TrimSpace(line[i+1:])
			if k != "" && v != "" {
				info.Headers[k] = v
			}
		}
	}
	info.Body = body
	return info
}

// isHTTPMethod 检查是否为HTTP方法
func isHTTPMethod(payload string) bool {
	methods := []string{"GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS ", "CONNECT ", "TRACE "}
	for _, method := range methods {
		if strings.HasPrefix(payload, method) {
			return true
		}
	}
	return false
}
