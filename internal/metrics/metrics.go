// Package metrics 定义 Prometheus 指标。每个 App 一个独立 Registry(不用全局默认注册表),
// 同一进程里起多个 App(集成测试、e2e)不会因重复注册而 panic。
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics 汇总服务端指标。
type Metrics struct {
	registry *prometheus.Registry

	HTTPRequests     *prometheus.CounterVec   // method, route, code
	HTTPDuration     *prometheus.HistogramVec // method, route
	WSConnections    prometheus.Gauge
	RateLimited      *prometheus.CounterVec // scope: ip / email / account
	RetentionDeleted *prometheus.CounterVec // kind: versions / trash_files / chunks / tokens
	RetentionErrors  prometheus.Counter
	BlobDeleteErrors prometheus.Counter
	NotifyReconnects prometheus.Counter
}

// New 创建并注册全部指标(含 Go 运行时与进程指标)。
func New() *Metrics {
	m := &Metrics{
		registry: prometheus.NewRegistry(),
		HTTPRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "typoza_http_requests_total",
			Help: "HTTP 请求数,按方法、路由模式、状态码。",
		}, []string{"method", "route", "code"}),
		HTTPDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "typoza_http_request_duration_seconds",
			Help:    "HTTP 请求耗时。",
			Buckets: prometheus.DefBuckets,
		}, []string{"method", "route"}),
		WSConnections: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "typoza_ws_connections",
			Help: "当前 WebSocket 通知连接数。",
		}),
		RateLimited: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "typoza_rate_limited_total",
			Help: "被限流拒绝的请求数。",
		}, []string{"scope"}),
		RetentionDeleted: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "typoza_retention_deleted_total",
			Help: "后台回收任务删除的对象数。",
		}, []string{"kind"}),
		RetentionErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "typoza_retention_errors_total",
			Help: "后台回收任务失败次数。",
		}),
		BlobDeleteErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "typoza_blob_delete_errors_total",
			Help: "删除对象存储对象失败次数(留下孤儿对象)。",
		}),
		NotifyReconnects: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "typoza_notify_reconnects_total",
			Help: "通知监听连接重连次数。",
		}),
	}
	m.registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		m.HTTPRequests, m.HTTPDuration, m.WSConnections, m.RateLimited,
		m.RetentionDeleted, m.RetentionErrors, m.BlobDeleteErrors, m.NotifyReconnects,
	)
	return m
}

// Handler 返回 /metrics 处理器。
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}
