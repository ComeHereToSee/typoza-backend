package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Vault 是库记录。
type Vault struct {
	ID            string
	EncryptedName string
	Seq           int64
	CreatedAt     time.Time
}

// checkVault 确认库存在且属于 userID:不存在 → ErrNotFound,属于他人 → ErrForbidden。
// lock 为 true 时对库行加排他锁:同一库的提交与永久删除由此串行化,seq 分配严格按提交顺序。
func checkVault(ctx context.Context, q querier, userID, vaultID string, lock bool) error {
	sql := `SELECT user_id::text FROM vaults WHERE id = $1`
	if lock {
		sql += ` FOR UPDATE`
	}
	var owner string
	err := q.QueryRow(ctx, sql, vaultID).Scan(&owner)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("查询库: %w", err)
	}
	if owner != userID {
		return ErrForbidden
	}
	return nil
}

// ListVaults 列出账号下的库。
func (s *Store) ListVaults(ctx context.Context, userID string) ([]Vault, error) {
	rows, err := s.pool.Query(ctx, `SELECT id::text, encrypted_name, seq, created_at
		FROM vaults WHERE user_id = $1 ORDER BY created_at, id`, userID)
	if err != nil {
		return nil, fmt.Errorf("列出库: %w", err)
	}
	defer rows.Close()
	out := []Vault{}
	for rows.Next() {
		var v Vault
		if err := rows.Scan(&v.ID, &v.EncryptedName, &v.Seq, &v.CreatedAt); err != nil {
			return nil, fmt.Errorf("读取库: %w", err)
		}
		v.CreatedAt = utc(v.CreatedAt)
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("列出库: %w", err)
	}
	return out, nil
}

// CreateVault 创建库;ID 已存在(无论属于谁)返回 ErrVaultExists。
func (s *Store) CreateVault(ctx context.Context, userID, vaultID, encryptedName string) (Vault, error) {
	v := Vault{ID: vaultID, EncryptedName: encryptedName}
	err := s.pool.QueryRow(ctx, `INSERT INTO vaults (id, user_id, encrypted_name) VALUES ($1, $2, $3)
		RETURNING seq, created_at`, vaultID, userID, encryptedName).Scan(&v.Seq, &v.CreatedAt)
	if isUniqueViolation(err, "vaults_pkey") {
		return Vault{}, ErrVaultExists
	}
	if err != nil {
		return Vault{}, fmt.Errorf("创建库: %w", err)
	}
	v.CreatedAt = utc(v.CreatedAt)
	return v, nil
}

// DeleteVault 删除库及其全部文件与版本(外键级联);块由回收任务按引用清理。
func (s *Store) DeleteVault(ctx context.Context, userID, vaultID string) error {
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		if err := checkVault(ctx, tx, userID, vaultID, true); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM vaults WHERE id = $1`, vaultID)
		return err
	})
	if err != nil && !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrForbidden) {
		return fmt.Errorf("删除库: %w", err)
	}
	return err
}
