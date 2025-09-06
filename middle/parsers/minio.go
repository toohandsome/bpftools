// Package parsers - MinIO/S3协议解析器 (HTTP/REST API)
package parsers

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/myserver/go-server/ebpf/middle/types"
)

// MinIOParser MinIO/S3协议解析器
type MinIOParser struct{}

// NewMinIOParser 创建MinIO解析器
func NewMinIOParser() *MinIOParser {
	return &MinIOParser{}
}

// GetProtocol 获取协议名称
func (p *MinIOParser) GetProtocol() string {
	return "minio"
}

// GetDefaultPort 获取默认端口
func (p *MinIOParser) GetDefaultPort() int {
	return 9000
}

// IsRequest 判断是否为请求
func (p *MinIOParser) IsRequest(data []byte) bool {
	// HTTP请求的特征：以HTTP方法开始
	dataStr := string(data)
	lines := strings.Split(dataStr, "\r\n")
	if len(lines) == 0 {
		return false
	}

	firstLine := strings.TrimSpace(lines[0])

	// 检查是否以HTTP方法开始
	httpMethods := []string{
		"GET", "PUT", "POST", "DELETE", "HEAD",
		"OPTIONS", "PATCH", "TRACE", "CONNECT",
	}

	for _, method := range httpMethods {
		if strings.HasPrefix(firstLine, method+" ") {
			return true
		}
	}

	return false
}

// IsResponse 判断是否为响应
func (p *MinIOParser) IsResponse(data []byte) bool {
	// HTTP响应的特征：以HTTP/版本开始
	dataStr := string(data)
	lines := strings.Split(dataStr, "\r\n")
	if len(lines) == 0 {
		return false
	}

	firstLine := strings.TrimSpace(lines[0])

	// 检查是否以HTTP/开始
	return strings.HasPrefix(firstLine, "HTTP/")
}

// ParseRequest 解析请求
func (p *MinIOParser) ParseRequest(data []byte) (*types.Message, error) {
	// 使用标准库解析HTTP请求
	reader := bytes.NewReader(data)
	bufReader := bufio.NewReader(reader)

	req, err := http.ReadRequest(bufReader)
	if err != nil {
		return nil, fmt.Errorf("解析HTTP请求失败: %v", err)
	}
	defer req.Body.Close()

	// 读取请求体
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
	}

	msg := &types.Message{
		Type:      "request",
		Data:      data,
		Size:      len(data),
		Timestamp: time.Now(),
	}

	// 解析S3操作
	s3Op := p.parseS3Operation(req)

	parsedData := S3Message{
		Type:        "Request",
		Method:      req.Method,
		URL:         req.URL.String(),
		Headers:     p.convertHeaders(req.Header),
		Body:        body,
		S3Operation: s3Op,
		RequestLine: fmt.Sprintf("%s %s %s", req.Method, req.URL.RequestURI(), req.Proto),
	}

	msg.ParsedData = parsedData
	msg.Command = s3Op.Operation
	msg.ID = p.generateRequestID(req, s3Op)

	return msg, nil
}

// ParseResponse 解析响应
func (p *MinIOParser) ParseResponse(data []byte) (*types.Message, error) {
	// 使用标准库解析HTTP响应
	reader := bytes.NewReader(data)
	bufReader := bufio.NewReader(reader)

	resp, err := http.ReadResponse(bufReader, nil)
	if err != nil {
		return nil, fmt.Errorf("解析HTTP响应失败: %v", err)
	}
	defer resp.Body.Close()

	// 读取响应体
	var body []byte
	if resp.Body != nil {
		body, _ = io.ReadAll(resp.Body)
	}

	msg := &types.Message{
		Type:      "response",
		Data:      data,
		Size:      len(data),
		Timestamp: time.Now(),
	}

	parsedData := S3Message{
		Type:       "Response",
		StatusCode: resp.StatusCode,
		Status:     resp.Status,
		Headers:    p.convertHeaders(resp.Header),
		Body:       body,
		StatusLine: fmt.Sprintf("%s %s", resp.Proto, resp.Status),
	}

	msg.ParsedData = parsedData
	msg.Command = "Response"
	msg.ID = p.generateResponseID(resp)

	return msg, nil
}

// S3Message S3/MinIO消息结构
type S3Message struct {
	Type        string              `json:"type"`
	Method      string              `json:"method,omitempty"`
	URL         string              `json:"url,omitempty"`
	StatusCode  int                 `json:"status_code,omitempty"`
	Status      string              `json:"status,omitempty"`
	Headers     map[string][]string `json:"headers"`
	Body        []byte              `json:"body,omitempty"`
	S3Operation *S3Operation        `json:"s3_operation,omitempty"`
	RequestLine string              `json:"request_line,omitempty"`
	StatusLine  string              `json:"status_line,omitempty"`
}

// S3Operation S3操作信息
type S3Operation struct {
	Operation  string `json:"operation"`
	Bucket     string `json:"bucket,omitempty"`
	Object     string `json:"object,omitempty"`
	VersionID  string `json:"version_id,omitempty"`
	UploadID   string `json:"upload_id,omitempty"`
	PartNumber int    `json:"part_number,omitempty"`
}

// parseS3Operation 解析S3操作
func (p *MinIOParser) parseS3Operation(req *http.Request) *S3Operation {
	op := &S3Operation{}

	// 解析路径获取bucket和object
	path := strings.TrimPrefix(req.URL.Path, "/")
	pathParts := strings.SplitN(path, "/", 2)

	if len(pathParts) > 0 && pathParts[0] != "" {
		op.Bucket = pathParts[0]
	}
	if len(pathParts) > 1 && pathParts[1] != "" {
		op.Object = pathParts[1]
	}

	// 解析查询参数
	query := req.URL.Query()

	// 确定操作类型
	switch req.Method {
	case "GET":
		if op.Object == "" {
			if query.Has("location") {
				op.Operation = "GetBucketLocation"
			} else if query.Has("acl") {
				op.Operation = "GetBucketAcl"
			} else if query.Has("policy") {
				op.Operation = "GetBucketPolicy"
			} else if query.Has("uploads") {
				op.Operation = "ListMultipartUploads"
			} else {
				op.Operation = "ListObjects"
			}
		} else {
			if query.Has("acl") {
				op.Operation = "GetObjectAcl"
			} else if query.Has("uploadId") {
				op.Operation = "ListParts"
				op.UploadID = query.Get("uploadId")
			} else {
				op.Operation = "GetObject"
			}
		}

	case "PUT":
		if op.Object == "" {
			op.Operation = "CreateBucket"
		} else {
			if query.Has("uploadId") && query.Has("partNumber") {
				op.Operation = "UploadPart"
				op.UploadID = query.Get("uploadId")
				if pn, err := strconv.Atoi(query.Get("partNumber")); err == nil {
					op.PartNumber = pn
				}
			} else if query.Has("acl") {
				op.Operation = "PutObjectAcl"
			} else {
				op.Operation = "PutObject"
			}
		}

	case "DELETE":
		if op.Object == "" {
			op.Operation = "DeleteBucket"
		} else {
			if query.Has("uploadId") {
				op.Operation = "AbortMultipartUpload"
				op.UploadID = query.Get("uploadId")
			} else {
				op.Operation = "DeleteObject"
			}
		}

	case "POST":
		if query.Has("delete") {
			op.Operation = "DeleteMultipleObjects"
		} else if query.Has("uploads") {
			op.Operation = "InitiateMultipartUpload"
		} else if query.Has("uploadId") {
			op.Operation = "CompleteMultipartUpload"
			op.UploadID = query.Get("uploadId")
		} else {
			op.Operation = "PostObject"
		}

	case "HEAD":
		if op.Object == "" {
			op.Operation = "HeadBucket"
		} else {
			op.Operation = "HeadObject"
		}

	case "OPTIONS":
		op.Operation = "OptionsObject"

	default:
		op.Operation = fmt.Sprintf("%s_%s", req.Method, "Unknown")
	}

	// 提取版本ID
	if versionID := query.Get("versionId"); versionID != "" {
		op.VersionID = versionID
	}

	return op
}

// convertHeaders 转换HTTP头
func (p *MinIOParser) convertHeaders(headers http.Header) map[string][]string {
	result := make(map[string][]string)
	for k, v := range headers {
		result[k] = v
	}
	return result
}

// generateRequestID 生成请求ID
func (p *MinIOParser) generateRequestID(req *http.Request, s3Op *S3Operation) string {
	// 使用请求的关键信息生成ID
	id := fmt.Sprintf("%s_%s", s3Op.Operation, s3Op.Bucket)
	if s3Op.Object != "" {
		id += "_" + s3Op.Object
	}
	if s3Op.UploadID != "" {
		id += "_" + s3Op.UploadID
	}

	// 添加时间戳确保唯一性
	id += fmt.Sprintf("_%d", time.Now().UnixNano())

	return id
}

// generateResponseID 生成响应ID
func (p *MinIOParser) generateResponseID(resp *http.Response) string {
	// 使用状态码和时间戳生成ID
	return fmt.Sprintf("resp_%d_%d", resp.StatusCode, time.Now().UnixNano())
}

// GetS3OperationFromHeaders 从HTTP头部获取S3操作信息
func (p *MinIOParser) GetS3OperationFromHeaders(headers http.Header) map[string]string {
	s3Headers := make(map[string]string)

	for key, values := range headers {
		lowerKey := strings.ToLower(key)
		if strings.HasPrefix(lowerKey, "x-amz-") ||
			strings.HasPrefix(lowerKey, "x-minio-") {
			if len(values) > 0 {
				s3Headers[key] = values[0]
			}
		}

		// 其他重要的S3相关头部
		switch lowerKey {
		case "content-md5", "content-type", "date", "authorization",
			"range", "if-match", "if-none-match", "if-modified-since",
			"if-unmodified-since", "etag", "last-modified":
			if len(values) > 0 {
				s3Headers[key] = values[0]
			}
		}
	}

	return s3Headers
}

// ExtractErrorInfo 从响应中提取错误信息
func (p *MinIOParser) ExtractErrorInfo(body []byte, statusCode int) map[string]string {
	errorInfo := make(map[string]string)
	errorInfo["status_code"] = fmt.Sprintf("%d", statusCode)

	// 如果是XML格式的错误响应
	bodyStr := string(body)
	if strings.Contains(bodyStr, "<Error>") {
		// 简单的XML解析，提取错误代码和消息
		if start := strings.Index(bodyStr, "<Code>"); start != -1 {
			start += 6
			if end := strings.Index(bodyStr[start:], "</Code>"); end != -1 {
				errorInfo["code"] = bodyStr[start : start+end]
			}
		}

		if start := strings.Index(bodyStr, "<Message>"); start != -1 {
			start += 9
			if end := strings.Index(bodyStr[start:], "</Message>"); end != -1 {
				errorInfo["message"] = bodyStr[start : start+end]
			}
		}

		if start := strings.Index(bodyStr, "<Resource>"); start != -1 {
			start += 10
			if end := strings.Index(bodyStr[start:], "</Resource>"); end != -1 {
				errorInfo["resource"] = bodyStr[start : start+end]
			}
		}
	}

	return errorInfo
}

// IsMultipartUpload 检查是否为分片上传操作
func (p *MinIOParser) IsMultipartUpload(parsedURL *url.URL) bool {
	query := parsedURL.Query()
	return query.Has("uploadId") || query.Has("uploads") || query.Has("partNumber")
}

// GetObjectSize 从HTTP头部获取对象大小
func (p *MinIOParser) GetObjectSize(headers http.Header) int64 {
	if contentLength := headers.Get("Content-Length"); contentLength != "" {
		if size, err := strconv.ParseInt(contentLength, 10, 64); err == nil {
			return size
		}
	}
	return 0
}
