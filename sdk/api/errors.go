package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// 错误码(协议 §3.2)。
const (
	CodeInvalidRequest     = "invalid_request"
	CodeMissingChunks      = "missing_chunks"
	CodeUnauthorized       = "unauthorized"
	CodeTokenExpired       = "token_expired"
	CodeRefreshReuse       = "refresh_reuse"
	CodeTOTPRequired       = "totp_required"
	CodeTOTPInvalid        = "totp_invalid"
	CodeRegistrationClosed = "registration_closed"
	CodeForbidden          = "forbidden"
	CodeNotFound           = "not_found"
	CodeEmailTaken         = "email_taken"
	CodeVaultExists        = "vault_exists"
	CodeVersionConflict    = "version_conflict"
	CodeNotDeleted         = "not_deleted"
	CodePayloadTooLarge    = "payload_too_large"
	CodeQuotaExceeded      = "quota_exceeded"
	CodeRateLimited        = "rate_limited"
	CodeInternal           = "internal"
)

// Error 是服务器返回的类型化错误(非 2xx 响应)。
type Error struct {
	// Status 是 HTTP 状态码。
	Status int
	// Code 是协议错误码;响应体不是协议格式时为空串。
	Code string
	// Message 是人读说明。
	Message string
	// Missing 是 missing_chunks 时缺失的块 ID。
	Missing []string
	// Head 是 version_conflict 时服务器上的当前版本;文件在服务器上不存在时为 nil。
	Head *Version
	// RetryAfter 是 429 响应的 Retry-After;未提供时为 0。
	RetryAfter time.Duration
}

func (e *Error) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("api: HTTP %d: %s", e.Status, e.Message)
	}
	return fmt.Sprintf("api: HTTP %d %s: %s", e.Status, e.Code, e.Message)
}

// IsCode 判断 err 链中是否有指定错误码的 *Error。
func IsCode(err error, code string) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == code
}

// IsAuthError 判断 err 是否表示登录态已失效、需要用户重新登录
// (401 且不是可自动处理的 token_expired / 需要二次验证的情形)。
func IsAuthError(err error) bool {
	var e *Error
	if !errors.As(err, &e) || e.Status != http.StatusUnauthorized {
		return false
	}
	switch e.Code {
	case CodeTokenExpired, CodeTOTPRequired, CodeTOTPInvalid:
		return false
	}
	return true
}

// errorBody 是协议统一错误体;附加字段在 error 对象内部(与服务端实现对齐)。
type errorBody struct {
	Error struct {
		Code    string   `json:"code"`
		Message string   `json:"message"`
		Missing []string `json:"missing"`
		Head    *Version `json:"head"`
	} `json:"error"`
}

// parseError 把非 2xx 响应解析为 *Error。响应体不是协议格式时保留原文前 200 字节作说明。
func parseError(status int, header http.Header, body []byte) *Error {
	e := &Error{Status: status}
	var eb errorBody
	if err := json.Unmarshal(body, &eb); err == nil && eb.Error.Code != "" {
		e.Code = eb.Error.Code
		e.Message = eb.Error.Message
		e.Missing = eb.Error.Missing
		e.Head = eb.Error.Head
	} else {
		msg := string(body)
		if len(msg) > 200 {
			msg = msg[:200]
		}
		if msg == "" {
			msg = http.StatusText(status)
		}
		e.Message = msg
	}
	if ra := header.Get("Retry-After"); ra != "" {
		if secs, err := strconv.Atoi(ra); err == nil && secs > 0 {
			e.RetryAfter = time.Duration(secs) * time.Second
		}
	}
	return e
}
