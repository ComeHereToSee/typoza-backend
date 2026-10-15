package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/ComeHereToSee/typoza-backend/internal/apierr"
)

var errRouteNotFound = apierr.NotFound("接口不存在")

// writeJSON 编码并写出 JSON 响应。v 用 any 接收:响应结构里有令牌字段,但这里是协议规定的出参,本就要下发给客户端。
func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		s.log.Error("编码响应失败", "err", err)
		status = http.StatusInternalServerError
		b = []byte(`{"error":{"code":"internal","message":"服务器内部错误"}}`)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	// 写失败只可能是客户端已断开,响应已无从补救。
	_, _ = w.Write(b)
}

// writeError 写出统一错误体 {"error":{"code","message",...附加字段}}。
// 非 *apierr.Error 的错误一律 500 internal,细节只进服务端日志(协议 §3.2)。
func (s *Server) writeError(w http.ResponseWriter, r *http.Request, err error) {
	var ae *apierr.Error
	if !errors.As(err, &ae) {
		info := requestInfo(r)
		if errors.Is(err, context.Canceled) && r.Context().Err() != nil {
			s.log.Info("客户端已断开,请求中止", "requestId", info.id, "err", err)
		} else {
			s.log.Error("内部错误", "requestId", info.id, "route", info.route, "err", err)
		}
		ae = apierr.Internal()
	}
	body := make(map[string]any, len(ae.Extra)+2)
	for k, v := range ae.Extra {
		body[k] = v
	}
	body["code"] = ae.Code
	body["message"] = ae.Message
	s.writeJSON(w, ae.Status, map[string]any{"error": body})
}

// decodeJSON 读取并解析恰好一个 JSON 值;超过 limit 返回 413 payload_too_large。
// 未知字段不报错,便于客户端向前兼容地增加字段。
func decodeJSON(w http.ResponseWriter, r *http.Request, limit int64, dst any) error {
	if r.ContentLength > limit {
		return apierr.PayloadTooLarge()
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		return jsonError(err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return jsonError(err)
		}
		return apierr.InvalidRequest("请求体只能包含一个 JSON 值")
	}
	return nil
}

func jsonError(err error) error {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		return apierr.PayloadTooLarge()
	}
	if errors.Is(err, io.EOF) {
		return apierr.InvalidRequest("请求体为空")
	}
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		return apierr.InvalidRequest(fmt.Sprintf("字段 %s 类型错误", typeErr.Field))
	}
	return apierr.InvalidRequest("请求体不是有效的 JSON")
}
