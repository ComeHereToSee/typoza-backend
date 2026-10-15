// typoza-server 是 Typoza 云端保存服务:账号、端到端加密存储、多设备增量同步、历史版本、回收站。
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ComeHereToSee/typoza-backend/internal/app"
	"github.com/ComeHereToSee/typoza-backend/internal/config"
)

const (
	shutdownTimeout   = 20 * time.Second
	startupTimeout    = 2 * time.Minute // 含等待其它实例完成迁移
	readHeaderTimeout = 10 * time.Second
	idleTimeout       = 120 * time.Second
)

func main() {
	if err := run(); err != nil {
		slog.Error("服务退出", "err", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	slog.SetDefault(log)
	log.Info("启动", "config", cfg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	startCtx, cancelStart := context.WithTimeout(ctx, startupTimeout)
	a, err := app.New(startCtx, cfg, log)
	cancelStart()
	if err != nil {
		return fmt.Errorf("初始化: %w", err)
	}

	// 不设 ReadTimeout / WriteTimeout:WebSocket 长连接与大块上传下载会被它们误杀;
	// 慢速攻击由 ReadHeaderTimeout、请求体上限与前置反向代理兜住。
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           a.Handler(),
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	servers := []*http.Server{srv}
	if cfg.MetricsListen != "" {
		servers = append(servers, &http.Server{
			Addr:              cfg.MetricsListen,
			Handler:           metricsMux(a.MetricsHandler()),
			ReadHeaderTimeout: readHeaderTimeout,
		})
	}

	errc := make(chan error, len(servers))
	for _, s := range servers {
		go func() {
			log.Info("开始监听", "addr", s.Addr)
			if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("监听 %s: %w", s.Addr, err)
				return
			}
			errc <- nil
		}()
	}

	var runErr error
	select {
	case <-ctx.Done():
		log.Info("收到停机信号,开始优雅停机", "timeout", shutdownTimeout.String())
	case runErr = <-errc:
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	var errs []error
	if runErr != nil {
		errs = append(errs, runErr)
	}
	for _, s := range servers {
		if err := s.Shutdown(shutdownCtx); err != nil {
			errs = append(errs, fmt.Errorf("关闭 %s: %w", s.Addr, err))
		}
	}
	// 在途 HTTP 请求处理完后再关后台任务与连接池;WebSocket 长连接在这里被主动断开。
	if err := a.Close(); err != nil {
		errs = append(errs, err)
	}
	log.Info("已停止")
	return errors.Join(errs...)
}

func metricsMux(h http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", h)
	return mux
}
