package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ComeHereToSee/typoza-backend/internal/notify"
)

// Version 是文件的一个版本(协议 §4.4 版本对象)。
type Version struct {
	FileID    string
	Version   int64
	Seq       int64
	Manifest  []byte
	Deleted   bool
	Size      int64
	DeviceID  string
	CreatedAt time.Time
}

const versionColumns = `fv.file_id::text, fv.version, fv.seq, fv.manifest, fv.deleted, fv.size,
	COALESCE(fv.device_id::text, ''), fv.created_at`

func scanVersion(row pgx.Row) (Version, error) {
	var v Version
	if err := row.Scan(&v.FileID, &v.Version, &v.Seq, &v.Manifest, &v.Deleted, &v.Size, &v.DeviceID, &v.CreatedAt); err != nil {
		return Version{}, err
	}
	v.CreatedAt = utc(v.CreatedAt)
	return v, nil
}

func collectVersions(rows pgx.Rows) ([]Version, error) {
	defer rows.Close()
	out := []Version{}
	for rows.Next() {
		v, err := scanVersion(rows)
		if err != nil {
			return nil, fmt.Errorf("读取版本: %w", err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("读取版本: %w", err)
	}
	return out, nil
}

// CommitInput 是一次文件提交。
type CommitInput struct {
	UserID      string
	DeviceID    string
	VaultID     string
	FileID      string
	BaseVersion int64
	Manifest    []byte
	Chunks      []string // 与清单内块列表一致,可含重复(同一文件里内容相同的块)
	Size        int64
	Deleted     bool
}

// CommitResult 是提交结果。
type CommitResult struct {
	Version int64
	Seq     int64
}

// Commit 在一个事务里完成提交(协议 §4.4):
//  1. 锁库行 —— 同一库的提交串行化,seq 分配顺序即提交可见顺序,changes 不会「先读到大号、后出现小号」;
//  2. baseVersion 必须等于当前版本,否则 *ConflictError(附当前 head);
//  3. 引用的块必须都已上传,否则 *MissingChunksError;块行加共享锁,防止与块回收并发时被删掉;
//  4. seq+1、写 files 的 head 与 file_versions;
//  5. pg_notify 通知各实例(随事务提交才真正发出)。
func (s *Store) Commit(ctx context.Context, in CommitInput) (CommitResult, error) {
	if in.Chunks == nil {
		in.Chunks = []string{}
	}
	var res CommitResult
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		if err := checkVault(ctx, tx, in.UserID, in.VaultID, true); err != nil {
			return err
		}

		var head int64
		err := tx.QueryRow(ctx, `SELECT head_version FROM files WHERE vault_id = $1 AND id = $2`, in.VaultID, in.FileID).Scan(&head)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			head = 0
		case err != nil:
			return fmt.Errorf("查询文件 head: %w", err)
		}
		if in.BaseVersion != head {
			conflict := &ConflictError{}
			if head > 0 {
				v, err := scanVersion(tx.QueryRow(ctx, `SELECT `+versionColumns+` FROM file_versions fv
					WHERE fv.vault_id = $1 AND fv.file_id = $2 AND fv.version = $3`, in.VaultID, in.FileID, head))
				if err != nil {
					return fmt.Errorf("读取 head 版本: %w", err)
				}
				conflict.Head = &v
			}
			return conflict
		}

		if missing, err := lockChunks(ctx, tx, in.UserID, in.Chunks); err != nil {
			return err
		} else if len(missing) > 0 {
			return &MissingChunksError{IDs: missing}
		}

		if err := tx.QueryRow(ctx, `UPDATE vaults SET seq = seq + 1 WHERE id = $1 RETURNING seq`, in.VaultID).Scan(&res.Seq); err != nil {
			return fmt.Errorf("分配 seq: %w", err)
		}
		res.Version = in.BaseVersion + 1

		// 再次进回收站时保留最早的删除时间,回收站 30 天从第一次删除算起。
		if _, err := tx.Exec(ctx, `INSERT INTO files (vault_id, id, head_version, head_seq, deleted, deleted_at)
				VALUES ($1, $2, $3, $4, $5::boolean, CASE WHEN $5::boolean THEN now() END)
			ON CONFLICT (vault_id, id) DO UPDATE SET
				head_version = EXCLUDED.head_version,
				head_seq     = EXCLUDED.head_seq,
				deleted      = EXCLUDED.deleted,
				deleted_at   = CASE WHEN EXCLUDED.deleted THEN COALESCE(files.deleted_at, EXCLUDED.deleted_at) END`,
			in.VaultID, in.FileID, res.Version, res.Seq, in.Deleted); err != nil {
			return fmt.Errorf("更新文件 head: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO file_versions (vault_id, file_id, version, seq, manifest, chunks, size, deleted, device_id)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			in.VaultID, in.FileID, res.Version, res.Seq, in.Manifest, in.Chunks, in.Size, in.Deleted, nullable(in.DeviceID)); err != nil {
			return fmt.Errorf("写入版本: %w", err)
		}

		payload, err := notify.Payload(in.UserID, in.VaultID, res.Seq)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT pg_notify($1, $2)`, notify.Channel, payload); err != nil {
			return fmt.Errorf("发送变更通知: %w", err)
		}
		return nil
	})
	if err != nil {
		var conflict *ConflictError
		var missing *MissingChunksError
		if errors.As(err, &conflict) || errors.As(err, &missing) || errors.Is(err, ErrNotFound) || errors.Is(err, ErrForbidden) {
			return CommitResult{}, err
		}
		return CommitResult{}, fmt.Errorf("提交文件: %w", err)
	}
	return res, nil
}

// lockChunks 对提交引用的块加共享锁并返回缺失的块 ID(去重、保持首次出现顺序)。
// 共享锁与块回收的 FOR UPDATE SKIP LOCKED 配合:回收任务跳过正被提交引用的块,
// 提交方则等回收事务结束后重新判断块是否还在。
func lockChunks(ctx context.Context, tx pgx.Tx, userID string, ids []string) ([]string, error) {
	uniq := dedupe(ids)
	if len(uniq) == 0 {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `SELECT id FROM chunks WHERE user_id = $1 AND id = ANY($2) ORDER BY id FOR SHARE`, userID, uniq)
	if err != nil {
		return nil, fmt.Errorf("锁定块: %w", err)
	}
	found, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("锁定块: %w", err)
	}
	have := make(map[string]bool, len(found))
	for _, id := range found {
		have[id] = true
	}
	var missing []string
	for _, id := range uniq {
		if !have[id] {
			missing = append(missing, id)
		}
	}
	return missing, nil
}

func dedupe(ids []string) []string {
	seen := make(map[string]bool, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// Changes 返回 seq > since 的文件当前版本(每文件只返回最新版本,按 seq 升序),以及是否还有更多。
func (s *Store) Changes(ctx context.Context, userID, vaultID string, since int64, limit int) ([]Version, bool, error) {
	if err := checkVault(ctx, s.pool, userID, vaultID, false); err != nil {
		return nil, false, err
	}
	rows, err := s.pool.Query(ctx, `SELECT `+versionColumns+`
		FROM files f JOIN file_versions fv ON fv.vault_id = f.vault_id AND fv.file_id = f.id AND fv.version = f.head_version
		WHERE f.vault_id = $1 AND f.head_seq > $2
		ORDER BY f.head_seq
		LIMIT $3`, vaultID, since, limit+1)
	if err != nil {
		return nil, false, fmt.Errorf("查询变更: %w", err)
	}
	out, err := collectVersions(rows)
	if err != nil {
		return nil, false, err
	}
	hasMore := len(out) > limit
	if hasMore {
		out = out[:limit]
	}
	return out, hasMore, nil
}

// Versions 返回文件全部保留的版本(新 → 旧);文件不存在返回 ErrNotFound。
func (s *Store) Versions(ctx context.Context, userID, vaultID, fileID string) ([]Version, error) {
	if err := checkVault(ctx, s.pool, userID, vaultID, false); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT `+versionColumns+` FROM file_versions fv
		WHERE fv.vault_id = $1 AND fv.file_id = $2 ORDER BY fv.version DESC`, vaultID, fileID)
	if err != nil {
		return nil, fmt.Errorf("查询历史版本: %w", err)
	}
	out, err := collectVersions(rows)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, ErrNotFound
	}
	return out, nil
}

// TrashItem 是回收站条目(墓碑版本)。
type TrashItem struct {
	FileID    string
	Version   int64
	Manifest  []byte
	DeletedAt time.Time
}

// Trash 列出库回收站:当前版本为墓碑的文件,最近删除的在前。
func (s *Store) Trash(ctx context.Context, userID, vaultID string) ([]TrashItem, error) {
	if err := checkVault(ctx, s.pool, userID, vaultID, false); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT f.id::text, fv.version, fv.manifest, COALESCE(f.deleted_at, fv.created_at)
		FROM files f JOIN file_versions fv ON fv.vault_id = f.vault_id AND fv.file_id = f.id AND fv.version = f.head_version
		WHERE f.vault_id = $1 AND f.deleted
		ORDER BY 4 DESC, f.id`, vaultID)
	if err != nil {
		return nil, fmt.Errorf("查询回收站: %w", err)
	}
	defer rows.Close()
	out := []TrashItem{}
	for rows.Next() {
		var t TrashItem
		if err := rows.Scan(&t.FileID, &t.Version, &t.Manifest, &t.DeletedAt); err != nil {
			return nil, fmt.Errorf("读取回收站: %w", err)
		}
		t.DeletedAt = utc(t.DeletedAt)
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("查询回收站: %w", err)
	}
	return out, nil
}

// PurgeFile 永久删除回收站里的文件及其全部版本;文件不存在 ErrNotFound,不在回收站 ErrNotDeleted。
func (s *Store) PurgeFile(ctx context.Context, userID, vaultID, fileID string) error {
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		if err := checkVault(ctx, tx, userID, vaultID, true); err != nil {
			return err
		}
		var deleted bool
		err := tx.QueryRow(ctx, `SELECT deleted FROM files WHERE vault_id = $1 AND id = $2`, vaultID, fileID).Scan(&deleted)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("查询文件: %w", err)
		}
		if !deleted {
			return ErrNotDeleted
		}
		_, err = tx.Exec(ctx, `DELETE FROM files WHERE vault_id = $1 AND id = $2`, vaultID, fileID)
		return err
	})
	if err != nil && !slices.ContainsFunc([]error{ErrNotFound, ErrForbidden, ErrNotDeleted}, func(e error) bool { return errors.Is(err, e) }) {
		return fmt.Errorf("永久删除文件: %w", err)
	}
	return err
}
