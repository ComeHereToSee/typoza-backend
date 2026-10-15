// Package app 把各模块装配成一个可运行的服务实例。
//
// 服务无状态(状态都在 PostgreSQL 与对象存储里),同一配置可起任意多个实例水平扩容;
// 跨实例的协调只有三处:迁移锁、回收任务锁、LISTEN/NOTIFY 通知。
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/ComeHereToSee/typoza-backend/internal/auth"
	"github.com/ComeHereToSee/typoza-backend/internal/blob"
	"github.com/ComeHereToSee/typoza-backend/internal/config"
	"github.com/ComeHereToSee/typoza-backend/internal/httpapi"
	"github.com/ComeHereToSee/typoza-backend/internal/metrics"
	"github.com/ComeHereToSee/typoza-backend/internal/migrate"
	"github.com/ComeHereToSee/typoza-backend/internal/notify"
	"github.com/ComeHereToSee/typoza-backend/internal/retention"
	"github.com/ComeHereToSee/typoza-backend/internal/service"
	"github.com/ComeHereToSee/typoza-backend/internal/store"
	"github.com/ComeHereToSee/typoza-backend/migrations"
)

// App 是一个服务实例。
type App struct {
	cfg       config.Config
	log       *slog.Logger
	pool      *pgxpool.Pool
	blobs     blob.Store
	metrics   *metrics.Metrics
	hub       *notify.Hub
	retention *retention.Runner
	handler   http.Handler

	cancel        context.CancelFunc
	wg            sync.WaitGroup
	shutdownTrace func(context.Context) error
	closeOnce     sync.Once
	closeErr      error
}

// New 连接数据库、执行迁移、打开对象存储,启动通知监听与后台回收任务,组装 HTTP 处理器。
// ctx 只约束启动过程;后台任务的生命周期由 Close 结束。
func New(ctx context.Context, cfg config.Config, log *slog.Logger) (_ *App, err error) {
	signer, err := auth.NewSigner(cfg.JWTPrivateKey, cfg.JWTKeyID)
	if err != nil {
		return nil, fmt.Errorf("JWT 签名密钥: %w", err)
	}
	box, err := auth.NewSecretBox(cfg.DataKey)
	if err != nil {
		return nil, fmt.Errorf("数据密钥: %w", err)
	}
	if len(cfg.EnumSecret) == 0 {
		return nil, errors.New("枚举密钥为空")
	}

	if err := migrate.Up(ctx, cfg.DatabaseURL, migrations.FS, log); err != nil {
		return nil, err
	}
	pool, err := store.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	a := &App{cfg: cfg, log: log, pool: pool, metrics: metrics.New(), hub: notify.NewHub()}
	defer func() {
		if err != nil {
			err = errors.Join(err, a.Close())
		}
	}()

	if a.blobs, err = blob.Open(ctx, cfg.Blob); err != nil {
		return nil, fmt.Errorf("对象存储: %w", err)
	}
	if cfg.TracingEnabled {
		if a.shutdownTrace, err = setupTracing(ctx); err != nil {
			return nil, err
		}
	}

	st := store.New(pool)
	svc := service.New(service.Options{
		Store:            st,
		Blobs:            a.blobs,
		Hasher:           auth.NewHasher(max(2, runtime.GOMAXPROCS(0))),
		Signer:           signer,
		SecretBox:        box,
		EnumSecret:       cfg.EnumSecret,
		RegistrationOpen: cfg.RegistrationOpen,
		QuotaBytes:       cfg.QuotaBytes,
		Metrics:          a.metrics,
		Log:              log,
	})
	a.retention = retention.New(st, a.blobs, cfg.Retention, log, a.metrics)

	var handler http.Handler = httpapi.New(httpapi.Deps{
		Service:        svc,
		Hub:            a.hub,
		Metrics:        a.metrics,
		Log:            log,
		Limits:         cfg.Limits,
		TrustedProxies: cfg.TrustedProxies,
		Ready:          a.ready,
		ServeMetrics:   cfg.MetricsListen == "",
	})
	if cfg.TracingEnabled {
		handler = otelhttp.NewHandler(handler, "typoza")
	}
	a.handler = handler

	// 后台任务脱离启动 ctx 的取消,只随 Close 结束。
	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	a.cancel = cancel
	a.wg.Go(func() {
		notify.Listen(runCtx, cfg.DatabaseURL, a.hub, log, a.metrics.NotifyReconnects.Inc)
	})
	a.wg.Go(func() { a.retention.Run(runCtx) })
	return a, nil
}

// Handler 返回对外 HTTP 处理器。
func (a *App) Handler() http.Handler { return a.handler }

// MetricsHandler 返回 Prometheus 指标处理器(配置了单独指标端口时由 main 挂载)。
func (a *App) MetricsHandler() http.Handler { return a.metrics.Handler() }

// Pool 返回数据库连接池(测试与运维工具用)。
func (a *App) Pool() *pgxpool.Pool { return a.pool }

// RunRetention 立即同步执行一轮后台回收(测试用;生产由定时任务驱动)。
func (a *App) RunRetention(ctx context.Context) (retention.Result, error) {
	return a.retention.RunOnce(ctx, time.Now())
}

// ready 检查数据库与对象存储(/readyz)。
func (a *App) ready(ctx context.Context) error {
	if err := a.pool.Ping(ctx); err != nil {
		return fmt.Errorf("数据库: %w", err)
	}
	if err := a.blobs.Ping(ctx); err != nil {
		return fmt.Errorf("对象存储: %w", err)
	}
	return nil
}

// Close 停止后台任务、断开 WebSocket、关闭连接池与追踪导出。可重复调用。
// 调用前应先让 http.Server.Shutdown 处理完在途请求;被升级为 WebSocket 的连接不受 Shutdown 管理,由这里断开。
func (a *App) Close() error {
	a.closeOnce.Do(func() {
		a.hub.Close()
		if a.cancel != nil {
			a.cancel()
		}
		a.wg.Wait()
		var errs []error
		if c, ok := a.blobs.(io.Closer); ok {
			if err := c.Close(); err != nil {
				errs = append(errs, fmt.Errorf("关闭对象存储: %w", err))
			}
		}
		if a.shutdownTrace != nil {
			if err := a.shutdownTrace(context.Background()); err != nil {
				errs = append(errs, fmt.Errorf("关闭追踪导出: %w", err))
			}
		}
		a.pool.Close()
		a.closeErr = errors.Join(errs...)
	})
	return a.closeErr
}
