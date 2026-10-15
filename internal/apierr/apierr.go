// Package apierr 定义对外错误:HTTP 状态码 + 协议错误码(同步协议 §3.2)+ 人读说明 + 附加字段。
//
// 业务层返回 *Error 表示「客户端可见的失败」;其余 error 一律按 500 internal 处理、细节只进日志。
package apierr

import "net/http"

// 错误码(同步协议 §3.2),字符串与协议逐字一致。
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

// Error 是客户端可见的错误。Extra 的键值会并入响应体的 error 对象(如 missing、head)。
type Error struct {
	Status  int
	Code    string
	Message string
	Extra   map[string]any
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// New 构造错误。
func New(status int, code, message string) *Error {
	return &Error{Status: status, Code: code, Message: message}
}

// With 返回附带额外字段的副本,不修改原值(包级预置错误可安全复用)。
func (e *Error) With(key string, value any) *Error {
	extra := make(map[string]any, len(e.Extra)+1)
	for k, v := range e.Extra {
		extra[k] = v
	}
	extra[key] = value
	return &Error{Status: e.Status, Code: e.Code, Message: e.Message, Extra: extra}
}

// 常用错误构造。
func InvalidRequest(message string) *Error {
	return New(http.StatusBadRequest, CodeInvalidRequest, message)
}

func Unauthorized() *Error {
	return New(http.StatusUnauthorized, CodeUnauthorized, "未登录、令牌无效或账号密码错误")
}

func TokenExpired() *Error {
	return New(http.StatusUnauthorized, CodeTokenExpired, "访问令牌已过期,请用刷新令牌换新")
}

func Forbidden() *Error {
	return New(http.StatusForbidden, CodeForbidden, "无权访问该资源")
}

func NotFound(message string) *Error {
	return New(http.StatusNotFound, CodeNotFound, message)
}

func PayloadTooLarge() *Error {
	return New(http.StatusRequestEntityTooLarge, CodePayloadTooLarge, "请求体超过上限")
}

func RateLimited() *Error {
	return New(http.StatusTooManyRequests, CodeRateLimited, "请求过于频繁,请稍后重试")
}

func Internal() *Error {
	return New(http.StatusInternalServerError, CodeInternal, "服务器内部错误")
}
