package store

import (
	"context"
	"fmt"
	"time"
)

// PruneVersions 裁剪历史版本(协议 §5):每文件只保留最近 keep 个且创建时间不早于 olderThan 的版本,
// 当前版本(head)无论多旧都保留。返回删除的版本数。
//
// 已知边界:每次全表开窗扫描,数据量很大时应改为按文件分批。
func (s *Store) PruneVersions(ctx context.Context, keep int, olderThan time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `WITH ranked AS (
			SELECT vault_id, file_id, version, created_at,
				row_number() OVER (PARTITION BY vault_id, file_id ORDER BY version DESC) AS rn
			FROM file_versions
		)
		DELETE FROM file_versions fv
		USING ranked r, files f
		WHERE fv.vault_id = r.vault_id AND fv.file_id = r.file_id AND fv.version = r.version
			AND f.vault_id = fv.vault_id AND f.id = fv.file_id
			AND fv.version <> f.head_version
			AND (r.rn > $1 OR r.created_at < $2)`, keep, olderThan)
	if err != nil {
		return 0, fmt.Errorf("裁剪历史版本: %w", err)
	}
	return tag.RowsAffected(), nil
}

// PurgeTrash 永久删除进回收站早于 deletedBefore 的文件(连同全部版本)。返回删除的文件数。
func (s *Store) PurgeTrash(ctx context.Context, deletedBefore time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM files WHERE deleted AND deleted_at < $1`, deletedBefore)
	if err != nil {
		return 0, fmt.Errorf("清空过期回收站: %w", err)
	}
	return tag.RowsAffected(), nil
}

// PurgeExpiredTokens 删除已过期的刷新令牌与恢复令牌。过期令牌本来就不可用,删掉只为控制表大小。
func (s *Store) PurgeExpiredTokens(ctx context.Context, now time.Time) (int64, error) {
	a, err := s.pool.Exec(ctx, `DELETE FROM refresh_tokens WHERE expires_at < $1`, now)
	if err != nil {
		return 0, fmt.Errorf("清理过期刷新令牌: %w", err)
	}
	b, err := s.pool.Exec(ctx, `DELETE FROM recovery_tokens WHERE expires_at < $1`, now)
	if err != nil {
		return 0, fmt.Errorf("清理过期恢复令牌: %w", err)
	}
	return a.RowsAffected() + b.RowsAffected(), nil
}
