package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ExistingChunks 返回 ids 中该账号已上传的块集合。
func (s *Store) ExistingChunks(ctx context.Context, userID string, ids []string) (map[string]bool, error) {
	have := make(map[string]bool, len(ids))
	if len(ids) == 0 {
		return have, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT id FROM chunks WHERE user_id = $1 AND id = ANY($2)`, userID, ids)
	if err != nil {
		return nil, fmt.Errorf("查询块: %w", err)
	}
	found, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("查询块: %w", err)
	}
	for _, id := range found {
		have[id] = true
	}
	return have, nil
}

// ChunkObject 返回块的对象键与大小;块不存在或不属于该账号返回 ErrNotFound。
func (s *Store) ChunkObject(ctx context.Context, userID, chunkID string) (string, int64, error) {
	var (
		key  string
		size int64
	)
	err := s.pool.QueryRow(ctx, `SELECT object_key, size FROM chunks WHERE user_id = $1 AND id = $2`, userID, chunkID).Scan(&key, &size)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", 0, ErrNotFound
	}
	if err != nil {
		return "", 0, fmt.Errorf("查询块: %w", err)
	}
	return key, size, nil
}

// Usage 返回账号已用字节与配额。
func (s *Store) Usage(ctx context.Context, userID string) (used, quota int64, err error) {
	err = s.pool.QueryRow(ctx, `SELECT used_bytes, quota_bytes FROM users WHERE id = $1`, userID).Scan(&used, &quota)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, 0, ErrNotFound
	}
	if err != nil {
		return 0, 0, fmt.Errorf("查询用量: %w", err)
	}
	return used, quota, nil
}

// InsertChunk 登记已写入对象存储的块,并在同一事务里累加用量。
// 返回 false 表示同 ID 的块已被并发上传登记(调用方应删掉自己刚写的对象);超配额返回 ErrQuotaExceeded 且不登记。
func (s *Store) InsertChunk(ctx context.Context, userID, chunkID string, size int64, objectKey string) (bool, error) {
	inserted := false
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO chunks (user_id, id, size, object_key) VALUES ($1, $2, $3, $4)
			ON CONFLICT (user_id, id) DO NOTHING`, userID, chunkID, size, objectKey)
		if err != nil {
			return fmt.Errorf("登记块: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return nil
		}
		// 条件更新同时完成「检查 + 扣减」,并发上传不会一起越过配额。
		tag, err = tx.Exec(ctx, `UPDATE users SET used_bytes = used_bytes + $2::bigint
			WHERE id = $1 AND used_bytes + $2::bigint <= quota_bytes`, userID, size)
		if err != nil {
			return fmt.Errorf("累加用量: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrQuotaExceeded
		}
		inserted = true
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrQuotaExceeded) {
			return false, err
		}
		return false, fmt.Errorf("上传块: %w", err)
	}
	return inserted, nil
}

// unreferenced 是「该块不再被账号下任何库的任何版本引用」的条件;chunks 别名为 c。
// fv.chunks 上有 GIN 索引,@> 可走索引。
const unreferenced = `NOT EXISTS (
	SELECT 1 FROM file_versions fv JOIN vaults v ON v.id = fv.vault_id
	WHERE v.user_id = c.user_id AND fv.chunks @> ARRAY[c.id])`

// CollectChunks 删除一批「无引用且早于 createdBefore 上传」的块记录,同时扣减用量,返回对应的对象键。
// 调用方在事务提交后删除对象:即使删对象失败也只是留下孤儿对象,不会出现「记录在、对象没了」。
//
// 与提交并发的正确性:第一步 FOR UPDATE SKIP LOCKED 锁住候选块(正被提交共享锁定的块会被跳过),
// 第二步用新快照再判断一次无引用 —— 在第一步之前已提交的引用此时可见,之后的提交会被行锁挡住、
// 等本事务结束后发现块已不在而返回 missing_chunks,由客户端重传。
func (s *Store) CollectChunks(ctx context.Context, createdBefore time.Time, batch int) ([]string, error) {
	var keys []string
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT c.user_id::text, c.id FROM chunks c
			WHERE c.created_at < $1 AND `+unreferenced+`
			ORDER BY c.created_at
			LIMIT $2
			FOR UPDATE OF c SKIP LOCKED`, createdBefore, batch)
		if err != nil {
			return fmt.Errorf("选择待回收块: %w", err)
		}
		var users, ids []string
		for rows.Next() {
			var u, id string
			if err := rows.Scan(&u, &id); err != nil {
				rows.Close()
				return fmt.Errorf("读取待回收块: %w", err)
			}
			users = append(users, u)
			ids = append(ids, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return fmt.Errorf("选择待回收块: %w", err)
		}
		if len(ids) == 0 {
			return nil
		}
		rows, err = tx.Query(ctx, `WITH del AS (
				DELETE FROM chunks c
				USING unnest($1::text[], $2::text[]) AS k(uid, cid)
				WHERE c.user_id = k.uid::uuid AND c.id = k.cid AND `+unreferenced+`
				RETURNING c.user_id, c.size, c.object_key
			), upd AS (
				UPDATE users u SET used_bytes = GREATEST(u.used_bytes - s.total, 0)
				FROM (SELECT user_id, sum(size)::bigint AS total FROM del GROUP BY user_id) s
				WHERE u.id = s.user_id
			)
			SELECT object_key FROM del`, users, ids)
		if err != nil {
			return fmt.Errorf("删除块记录: %w", err)
		}
		keys, err = pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return fmt.Errorf("删除块记录: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("回收块: %w", err)
	}
	return keys, nil
}
