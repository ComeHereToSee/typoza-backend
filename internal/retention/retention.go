// Package retention 是后台回收任务(协议 §5):裁剪历史版本、清空过期回收站、回收无引用的块。
//
// 多实例部署时用 PostgreSQL advisory lock 保证同一时刻只有一个实例在跑;没拿到锁的实例本轮直接跳过。
package retention

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/ComeHereToSee/typoza-backend/internal/blob"
	"github.com/ComeHereToSee/typoza-backend/internal/config"
	"github.com/ComeHereToSee/typoza-backend/internal/metrics"
	"github.com/ComeHereToSee/typoza-backend/internal/store"
)

const (
	lockName   = "typoza-retention"
	chunkBatch = 500
	// startDelay 是启动后首轮的延迟:滚动发布时避免新实例一启动就抢着跑。
	startDelay = time.Minute
)

// Result 是一轮回收的统计。
type Result struct {
	Skipped       bool // 其它实例正在跑
	Versions      int64
	TrashFiles    int64
	Chunks        int64
	Tokens        int64
	OrphanedBlobs int // 记录已删、但对象删除失败的数量
}

// Runner 执行回收。
type Runner struct {
	store   *store.Store
	blobs   blob.Store
	cfg     config.Retention
	log     *slog.Logger
	metrics *metrics.Metrics
}

// New 创建回收任务。
func New(st *store.Store, blobs blob.Store, cfg config.Retention, log *slog.Logger, m *metrics.Metrics) *Runner {
	return &Runner{store: st, blobs: blobs, cfg: cfg, log: log, metrics: m}
}

// Run 按 cfg.Interval 周期执行,直到 ctx 取消。Interval 为 0 时立即返回。
func (r *Runner) Run(ctx context.Context) {
	if r.cfg.Interval <= 0 {
		return
	}
	timer := time.NewTimer(startDelay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if _, err := r.RunOnce(ctx, time.Now()); err != nil && ctx.Err() == nil {
			r.metrics.RetentionErrors.Inc()
			r.log.Error("后台回收任务失败", "err", err)
		}
		timer.Reset(r.cfg.Interval)
	}
}

// RunOnce 以 now 为基准执行一轮回收。
func (r *Runner) RunOnce(ctx context.Context, now time.Time) (Result, error) {
	var res Result
	acquired, err := r.store.WithTryLock(ctx, lockName, func(ctx context.Context) error {
		var err error
		if res.Versions, err = r.store.PruneVersions(ctx, r.cfg.MaxVersions, now.Add(-r.cfg.VersionMaxAge)); err != nil {
			return err
		}
		if res.TrashFiles, err = r.store.PurgeTrash(ctx, now.Add(-r.cfg.TrashTTL)); err != nil {
			return err
		}
		// 先清版本与回收站,再回收块:被清掉的版本所引用的块本轮就能回收。
		for {
			keys, err := r.store.CollectChunks(ctx, now.Add(-r.cfg.ChunkGrace), chunkBatch)
			if err != nil {
				return err
			}
			res.Chunks += int64(len(keys))
			for _, key := range keys {
				if err := r.blobs.Delete(ctx, key); err != nil {
					res.OrphanedBlobs++
					r.metrics.BlobDeleteErrors.Inc()
					r.log.Error("删除块对象失败,留下孤儿对象", "key", key, "err", err)
				}
			}
			if len(keys) < chunkBatch {
				break
			}
		}
		if res.Tokens, err = r.store.PurgeExpiredTokens(ctx, now); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return res, fmt.Errorf("回收任务: %w", err)
	}
	if !acquired {
		res.Skipped = true
		return res, nil
	}
	r.metrics.RetentionDeleted.WithLabelValues("versions").Add(float64(res.Versions))
	r.metrics.RetentionDeleted.WithLabelValues("trash_files").Add(float64(res.TrashFiles))
	r.metrics.RetentionDeleted.WithLabelValues("chunks").Add(float64(res.Chunks))
	r.metrics.RetentionDeleted.WithLabelValues("tokens").Add(float64(res.Tokens))
	r.log.Info("后台回收完成", "versions", res.Versions, "trashFiles", res.TrashFiles,
		"chunks", res.Chunks, "tokens", res.Tokens, "orphanedBlobs", res.OrphanedBlobs)
	return res, nil
}
