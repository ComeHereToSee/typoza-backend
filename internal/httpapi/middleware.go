package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/ComeHereToSee/typoza-backend/internal/apierr"
	"github.com/ComeHereToSee/typoza-backend/internal/service"
)

// reqInfo 是一次请求在中间件之间共享的可变信息(请求 ID、客户端 IP、路由模式、账号)。
type reqInfo struct {
	id     string
	ip     string
	route  string
	userID string
}

type reqInfoKey struct{}

func infoFrom(ctx context.Context) *reqInfo {
	info, _ := ctx.Value(reqInfoKey{}).(*reqInfo)
	return info
}

// requestInfo 返回请求信息;在中间件链之外调用(单元测试)时返回空信息。
func requestInfo(r *http.Request) *reqInfo {
	if info := infoFrom(r.Context()); info != nil {
		return info
	}
	return &reqInfo{}
}

// observe 是最外层中间件:请求 ID、客户端 IP、安全响应头、panic 恢复、访问日志与指标。
func (s *Server) observe(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		info := &reqInfo{id: requestID(r), ip: s.clientIP(r)}
		setSecurityHeaders(w.Header())
		w.Header().Set("X-Request-Id", info.id)
		rec := &statusRecorder{ResponseWriter: w}
		r = r.WithContext(context.WithValue(r.Context(), reqInfoKey{}, info))

		s.serveRecovering(next, rec, r)

		status := rec.status
		if status == 0 {
			status = http.StatusOK
		}
		route := info.route
		if route == "" {
			route = "unmatched"
		}
		method := normalizeMethod(r.Method)
		elapsed := time.Since(start)
		s.metrics.HTTPRequests.WithLabelValues(method, route, strconv.Itoa(status)).Inc()
		s.metrics.HTTPDuration.WithLabelValues(method, route).Observe(elapsed.Seconds())

		level := slog.LevelInfo
		if status >= http.StatusInternalServerError {
			level = slog.LevelError
		}
		s.log.LogAttrs(r.Context(), level, "http",
			slog.String("requestId", info.id),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.String("route", route),
			slog.Int("status", status),
			slog.Int64("bytes", rec.bytes),
			slog.Float64("durationMs", float64(elapsed.Microseconds())/1000),
			slog.String("ip", info.ip),
			slog.String("userId", info.userID),
		)
	})
}

// serveRecovering 调用下游并把 panic 转成 500 internal(细节与堆栈只进日志)。
// http.ErrAbortHandler 是标准库约定的「中止响应」信号,原样继续抛出。
func (s *Server) serveRecovering(next http.Handler, rec *statusRecorder, r *http.Request) {
	defer func() {
		v := recover()
		if v == nil {
			return
		}
		if err, ok := v.(error); ok && errors.Is(err, http.ErrAbortHandler) {
			panic(v)
		}
		s.log.Error("处理请求时 panic", "requestId", requestInfo(r).id, "panic", v, "stack", string(debug.Stack()))
		if rec.status == 0 {
			s.writeError(rec, r, apierr.Internal())
		}
	}()
	next.ServeHTTP(rec, r)
}

func normalizeMethod(m string) string {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodOptions:
		return m
	}
	return "OTHER" // 防止任意方法名撑爆指标基数
}

func setSecurityHeaders(h http.Header) {
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	h.Set("Cache-Control", "no-store")
	h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
}

// requestID 沿用上游传来的合规 X-Request-Id(便于跨反向代理串联日志),否则生成新的。
func requestID(r *http.Request) string {
	if id := r.Header.Get("X-Request-Id"); validRequestID(id) {
		return id
	}
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic("httpapi: 读取系统随机数失败: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func validRequestID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// clientIP 取客户端 IP:直连来源不在受信代理列表时直接用它;
// 否则从右往左跳过受信代理,取 X-Forwarded-For 里第一个不受信的地址(左侧的值客户端可伪造,不能直接取最左)。
func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	addr = addr.Unmap()
	if !s.trusted(addr) {
		return addr.String()
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop := strings.TrimSpace(hops[i])
		if hop == "" {
			continue
		}
		ip, err := netip.ParseAddr(hop)
		if err != nil {
			// 格式不对的值无法信任,以最近一个受信跳为准。
			return addr.String()
		}
		ip = ip.Unmap()
		if !s.trusted(ip) {
			return ip.String()
		}
		addr = ip
	}
	return addr.String()
}

func (s *Server) trusted(ip netip.Addr) bool {
	for _, p := range s.proxies {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// limitIP 对未认证接口按客户端 IP 限流。
func (s *Server) limitIP(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if ok, wait := s.ipLimiter.Allow(requestInfo(r).ip); !ok {
			s.rateLimited(w, r, "ip", wait)
			return
		}
		next(w, r)
	}
}

// allowEmail 对登录、恢复与二次验证按账号标识限流;返回 false 时已写好 429 响应。
func (s *Server) allowEmail(w http.ResponseWriter, r *http.Request, key string) bool {
	if ok, wait := s.emailLimiter.Allow(key); !ok {
		s.rateLimited(w, r, "email", wait)
		return false
	}
	return true
}

func (s *Server) rateLimited(w http.ResponseWriter, r *http.Request, scope string, wait time.Duration) {
	s.metrics.RateLimited.WithLabelValues(scope).Inc()
	secs := (wait + time.Second - 1) / time.Second
	w.Header().Set("Retry-After", strconv.FormatInt(int64(secs), 10))
	s.writeError(w, r, apierr.RateLimited())
}

// authed 校验 Bearer 访问令牌与设备状态,再按账号限流,通过后把调用方交给 handler。
func (s *Server) authed(next func(http.ResponseWriter, *http.Request, service.Principal)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r)
		if !ok {
			s.writeError(w, r, apierr.Unauthorized())
			return
		}
		info := requestInfo(r)
		p, err := s.svc.Authenticate(r.Context(), token, info.ip)
		if err != nil {
			s.writeError(w, r, err)
			return
		}
		info.userID = p.UserID
		if ok, wait := s.accountLimiter.Allow(p.UserID); !ok {
			s.rateLimited(w, r, "account", wait)
			return
		}
		next(w, r, p)
	}
}

func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	scheme, token, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}

// statusRecorder 记录状态码与字节数。实现 Unwrap,http.ResponseController 与 WebSocket 升级
// 能穿透它拿到底层连接的 Hijacker / Flusher。
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *statusRecorder) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusRecorder) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

func (w *statusRecorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }
