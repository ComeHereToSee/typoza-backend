// Package httpapi 是 HTTP 边界:路由、中间件、请求校验与响应编码。handler 只做解码、校验、调用业务层、编码。
package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/ComeHereToSee/typoza-backend/internal/config"
	"github.com/ComeHereToSee/typoza-backend/internal/metrics"
	"github.com/ComeHereToSee/typoza-backend/internal/notify"
	"github.com/ComeHereToSee/typoza-backend/internal/ratelimit"
	"github.com/ComeHereToSee/typoza-backend/internal/service"
)

// 请求体上限。
const (
	jsonBodyLimit   = 1 << 20          // 普通 JSON 请求 1 MiB(chunks/check 1000 个 ID 约 70 KiB)
	commitBodyLimit = 8 << 20          // 提交含加密清单与块列表,大文件的块列表可达数 MiB
	chunkBodyLimit  = 4<<20 + 64       // 协议 §4.3:块密文 ≤ 4 MiB + 64 字节
	readyTimeout    = 3 * time.Second  // 就绪探针的依赖检查超时
	wsPingInterval  = 30 * time.Second // 协议 §4.5
	wsWriteTimeout  = 10 * time.Second
)

// Deps 是 HTTP 层依赖。
type Deps struct {
	Service        *service.Service
	Hub            *notify.Hub
	Metrics        *metrics.Metrics
	Log            *slog.Logger
	Limits         config.Limits
	TrustedProxies []netip.Prefix
	// Ready 检查数据库与对象存储是否可用(/readyz)。
	Ready func(ctx context.Context) error
	// ServeMetrics 为 true 时在主端口挂载 /metrics(未单独配置指标端口时)。
	ServeMetrics bool
}

// Server 持有路由与限流器。
type Server struct {
	svc            *service.Service
	hub            *notify.Hub
	metrics        *metrics.Metrics
	log            *slog.Logger
	proxies        []netip.Prefix
	ready          func(ctx context.Context) error
	ipLimiter      *ratelimit.Limiter
	emailLimiter   *ratelimit.Limiter
	accountLimiter *ratelimit.Limiter
	mux            *http.ServeMux
}

// New 组装路由与中间件,返回最终的 http.Handler。
func New(d Deps) http.Handler {
	s := &Server{
		svc:            d.Service,
		hub:            d.Hub,
		metrics:        d.Metrics,
		log:            d.Log,
		proxies:        d.TrustedProxies,
		ready:          d.Ready,
		ipLimiter:      ratelimit.New(d.Limits.IPPerMinute),
		emailLimiter:   ratelimit.New(d.Limits.EmailPerMinute),
		accountLimiter: ratelimit.New(d.Limits.AccountPerMinute),
		mux:            http.NewServeMux(),
	}
	s.routes(d.ServeMetrics)
	return s.observe(s.mux)
}

func (s *Server) routes(serveMetrics bool) {
	s.handle("GET /healthz", s.healthz)
	s.handle("GET /readyz", s.readyz)
	if serveMetrics {
		h := s.metrics.Handler()
		s.handle("GET /metrics", h.ServeHTTP)
	}

	// 账号(未认证,按 IP 限流)
	s.handle("POST /v1/auth/prelogin", s.limitIP(s.prelogin))
	s.handle("POST /v1/auth/register", s.limitIP(s.register))
	s.handle("POST /v1/auth/login", s.limitIP(s.login))
	s.handle("POST /v1/auth/refresh", s.limitIP(s.refresh))
	s.handle("POST /v1/auth/recover/begin", s.limitIP(s.recoverBegin))
	s.handle("POST /v1/auth/recover/finish", s.limitIP(s.recoverFinish))

	// 账号(已认证)
	s.handle("POST /v1/auth/logout", s.authed(s.logout))
	s.handle("GET /v1/account", s.authed(s.account))
	s.handle("DELETE /v1/account", s.authed(s.deleteAccount))
	s.handle("POST /v1/account/password", s.authed(s.changePassword))
	s.handle("POST /v1/account/totp/setup", s.authed(s.totpSetup))
	s.handle("POST /v1/account/totp/enable", s.authed(s.totpEnable))
	s.handle("POST /v1/account/totp/disable", s.authed(s.totpDisable))
	s.handle("GET /v1/devices", s.authed(s.devices))
	s.handle("DELETE /v1/devices/{deviceId}", s.authed(s.revokeDevice))

	// 库与同步
	s.handle("GET /v1/vaults", s.authed(s.listVaults))
	s.handle("POST /v1/vaults", s.authed(s.createVault))
	s.handle("DELETE /v1/vaults/{vaultId}", s.authed(s.deleteVault))
	s.handle("POST /v1/chunks/check", s.authed(s.checkChunks))
	s.handle("PUT /v1/chunks/{chunkId}", s.authed(s.putChunk))
	s.handle("GET /v1/chunks/{chunkId}", s.authed(s.getChunk))
	s.handle("POST /v1/vaults/{vaultId}/files/{fileId}/commit", s.authed(s.commit))
	s.handle("GET /v1/vaults/{vaultId}/changes", s.authed(s.changes))
	s.handle("GET /v1/vaults/{vaultId}/files/{fileId}/versions", s.authed(s.versions))
	s.handle("GET /v1/vaults/{vaultId}/trash", s.authed(s.trash))
	s.handle("DELETE /v1/vaults/{vaultId}/files/{fileId}", s.authed(s.purgeFile))

	// 实时通知
	s.handle("GET /v1/events", s.authed(s.events))

	// 其余路径统一返回协议格式的 404。
	s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.writeError(w, r, errRouteNotFound)
	})
}

// handle 注册路由,并把路由模式记进请求信息,供访问日志与指标按模式(而不是带 ID 的原始路径)聚合。
func (s *Server) handle(pattern string, h http.HandlerFunc) {
	s.mux.Handle(pattern, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if info := infoFrom(r.Context()); info != nil {
			info.route = pattern
		}
		h(w, r)
	}))
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// readyz 检查依赖;失败细节只进日志,不对外暴露。
func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), readyTimeout)
	defer cancel()
	if err := s.ready(ctx); err != nil {
		s.log.Warn("就绪检查失败", "err", err)
		s.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}
