package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Device 是设备列表项。
type Device struct {
	ID         string
	Name       string
	Platform   string
	CreatedAt  time.Time
	LastSeenAt time.Time
}

func insertDevice(ctx context.Context, q querier, userID string, d NewDevice) error {
	_, err := q.Exec(ctx, `INSERT INTO devices (id, user_id, name, platform) VALUES ($1, $2, $3, $4)`,
		d.ID, userID, d.Name, d.Platform)
	if err != nil {
		return fmt.Errorf("创建设备: %w", err)
	}
	return nil
}

func insertRefresh(ctx context.Context, q querier, deviceID string, r NewRefresh) error {
	var parent any
	if r.ParentID != "" {
		parent = r.ParentID
	}
	_, err := q.Exec(ctx, `INSERT INTO refresh_tokens (id, device_id, family_id, token_hash, expires_at, parent_id)
		VALUES ($1, $2, $3, $4, $5, $6)`, r.ID, deviceID, r.FamilyID, r.Hash, r.ExpiresAt, parent)
	if err != nil {
		return fmt.Errorf("写入刷新令牌: %w", err)
	}
	return nil
}

// revokeDevice 吊销一个设备及其整条令牌链。
func revokeDevice(ctx context.Context, q querier, deviceID string, now time.Time) error {
	if _, err := q.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = $2 WHERE device_id = $1 AND revoked_at IS NULL`,
		deviceID, now); err != nil {
		return fmt.Errorf("吊销设备令牌: %w", err)
	}
	if _, err := q.Exec(ctx, `UPDATE devices SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL`,
		deviceID, now); err != nil {
		return fmt.Errorf("吊销设备: %w", err)
	}
	return nil
}

// revokeDevices 吊销账号下除 keepDeviceID 外的全部设备与令牌;keepDeviceID 为空表示全部吊销。
func revokeDevices(ctx context.Context, q querier, userID, keepDeviceID string, now time.Time) error {
	// 用 uuid 列与 text 参数比较时要显式转换;空串表示「不保留任何设备」。
	if _, err := q.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = $3
		WHERE revoked_at IS NULL AND device_id IN (
			SELECT id FROM devices WHERE user_id = $1 AND id::text <> $2::text)`,
		userID, keepDeviceID, now); err != nil {
		return fmt.Errorf("吊销其它设备令牌: %w", err)
	}
	if _, err := q.Exec(ctx, `UPDATE devices SET revoked_at = $3
		WHERE user_id = $1 AND id::text <> $2::text AND revoked_at IS NULL`,
		userID, keepDeviceID, now); err != nil {
		return fmt.Errorf("吊销其它设备: %w", err)
	}
	return nil
}

// LoginDevice 登录时落设备与新令牌链。reuseID 非空且属于该账号时复用设备记录并吊销其旧令牌链(协议 §4.1),
// 否则新建设备 d。返回实际使用的设备 ID。
func (s *Store) LoginDevice(ctx context.Context, userID, reuseID string, d NewDevice, r NewRefresh, now time.Time) (string, error) {
	deviceID := d.ID
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		if reuseID != "" {
			tag, err := tx.Exec(ctx, `UPDATE devices SET name = $3, platform = $4, revoked_at = NULL, last_seen_at = $5
				WHERE id = $1 AND user_id = $2`, reuseID, userID, d.Name, d.Platform, now)
			if err != nil {
				return fmt.Errorf("复用设备: %w", err)
			}
			if tag.RowsAffected() == 1 {
				deviceID = reuseID
				if _, err := tx.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = $2 WHERE device_id = $1 AND revoked_at IS NULL`,
					reuseID, now); err != nil {
					return fmt.Errorf("吊销旧令牌链: %w", err)
				}
				return insertRefresh(ctx, tx, deviceID, r)
			}
		}
		if err := insertDevice(ctx, tx, userID, d); err != nil {
			return err
		}
		return insertRefresh(ctx, tx, deviceID, r)
	})
	if err != nil {
		return "", fmt.Errorf("登录落库: %w", err)
	}
	return deviceID, nil
}

// RefreshReuseGrace 是刷新令牌轮换后的宽限期(协议 §3.1):期内旧令牌再次出现、且它换出的新令牌
// 从未被用过,说明客户端没收到上次的响应(网络中断、进程被杀),作废那个没送达的新令牌并重新签发。
const RefreshReuseGrace = 30 * time.Second

// RotateRefresh 用旧令牌摘要换新令牌(轮换)。
//   - 不存在、已过期、已吊销:ErrTokenInvalid;
//   - 已用过:宽限期内且换出的新令牌没被用过 → 重新签发;否则视为被重放,
//     吊销该设备整条令牌链并提交,返回 ErrRefreshReuse(协议 §3.1)。
//
// 行锁保证同一令牌的并发刷新串行执行。
func (s *Store) RotateRefresh(ctx context.Context, hash []byte, next NewRefresh, now time.Time) (userID, deviceID string, err error) {
	reused := false
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		var (
			tokenID, familyID string
			expiresAt         time.Time
			usedAt, revokedAt *time.Time
			deviceRevokedAt   *time.Time
		)
		err := tx.QueryRow(ctx, `SELECT rt.id::text, rt.family_id::text, rt.device_id::text, rt.expires_at, rt.used_at, rt.revoked_at,
				d.user_id::text, d.revoked_at
			FROM refresh_tokens rt JOIN devices d ON d.id = rt.device_id
			WHERE rt.token_hash = $1
			FOR UPDATE OF rt`, hash).
			Scan(&tokenID, &familyID, &deviceID, &expiresAt, &usedAt, &revokedAt, &userID, &deviceRevokedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrTokenInvalid
		}
		if err != nil {
			return fmt.Errorf("查询刷新令牌: %w", err)
		}
		if revokedAt != nil || deviceRevokedAt != nil {
			return ErrTokenInvalid
		}
		if usedAt != nil {
			retry, err := lostResponseRetry(ctx, tx, tokenID, *usedAt, now)
			if err != nil {
				return err
			}
			if !retry {
				reused = true
				return revokeDevice(ctx, tx, deviceID, now)
			}
		} else {
			if !expiresAt.After(now) {
				return ErrTokenInvalid
			}
			if _, err := tx.Exec(ctx, `UPDATE refresh_tokens SET used_at = $2 WHERE id = $1`, tokenID, now); err != nil {
				return fmt.Errorf("标记令牌已用: %w", err)
			}
		}
		next.FamilyID = familyID
		next.ParentID = tokenID
		if err := insertRefresh(ctx, tx, deviceID, next); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE devices SET last_seen_at = $2 WHERE id = $1`, deviceID, now); err != nil {
			return fmt.Errorf("更新设备活跃时间: %w", err)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrTokenInvalid) {
			return "", "", err
		}
		return "", "", fmt.Errorf("轮换刷新令牌: %w", err)
	}
	if reused {
		return userID, deviceID, ErrRefreshReuse
	}
	return userID, deviceID, nil
}

// lostResponseRetry 判断已用令牌的再次出现是否是「没收到响应的重试」;是则作废它换出的、
// 从未被用过的新令牌(只保留一条有效令牌链),由调用方重新签发。
func lostResponseRetry(ctx context.Context, tx pgx.Tx, tokenID string, usedAt, now time.Time) (bool, error) {
	if now.Sub(usedAt) > RefreshReuseGrace {
		return false, nil
	}
	var childUsed bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM refresh_tokens WHERE parent_id = $1 AND used_at IS NOT NULL)`,
		tokenID).Scan(&childUsed)
	if err != nil {
		return false, fmt.Errorf("查询换出的刷新令牌: %w", err)
	}
	if childUsed {
		return false, nil
	}
	if _, err := tx.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = $2 WHERE parent_id = $1 AND revoked_at IS NULL`, tokenID, now); err != nil {
		return false, fmt.Errorf("作废未送达的刷新令牌: %w", err)
	}
	return true, nil
}

// RevokeDevice 吊销账号下的某个设备。设备不存在、不属于该账号或已吊销时返回 ErrNotFound。
func (s *Store) RevokeDevice(ctx context.Context, userID, deviceID string, now time.Time) error {
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var id string
		err := tx.QueryRow(ctx, `SELECT id::text FROM devices WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL FOR UPDATE`,
			deviceID, userID).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("查询设备: %w", err)
		}
		return revokeDevice(ctx, tx, deviceID, now)
	})
	if err != nil && !errors.Is(err, ErrNotFound) {
		return fmt.Errorf("吊销设备: %w", err)
	}
	return err
}

// ListDevices 列出账号下未吊销(含未登出)的设备。
func (s *Store) ListDevices(ctx context.Context, userID string) ([]Device, error) {
	rows, err := s.pool.Query(ctx, `SELECT id::text, name, platform, created_at, last_seen_at
		FROM devices WHERE user_id = $1 AND revoked_at IS NULL ORDER BY created_at, id`, userID)
	if err != nil {
		return nil, fmt.Errorf("列出设备: %w", err)
	}
	defer rows.Close()
	out := []Device{}
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.ID, &d.Name, &d.Platform, &d.CreatedAt, &d.LastSeenAt); err != nil {
			return nil, fmt.Errorf("读取设备: %w", err)
		}
		d.CreatedAt, d.LastSeenAt = utc(d.CreatedAt), utc(d.LastSeenAt)
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("列出设备: %w", err)
	}
	return out, nil
}

// TouchDevice 确认设备未被吊销,并顺带刷新最近活跃时间(最多每分钟写一次,避免每个请求都写库)。
// 认证中间件每个请求都调用它,所以登出、吊销、改密后旧访问令牌立即失效,不必等 15 分钟过期。
func (s *Store) TouchDevice(ctx context.Context, userID, deviceID string, now time.Time) (bool, error) {
	var active bool
	err := s.pool.QueryRow(ctx, `WITH d AS (
			SELECT id FROM devices WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL
		), touched AS (
			UPDATE devices SET last_seen_at = $3::timestamptz
			WHERE id IN (SELECT id FROM d) AND last_seen_at < $3::timestamptz - interval '1 minute'
		)
		SELECT EXISTS (SELECT 1 FROM d)`, deviceID, userID, now).Scan(&active)
	if err != nil {
		return false, fmt.Errorf("校验设备状态: %w", err)
	}
	return active, nil
}

// LogoutDevice 吊销当前设备的令牌链(登出)。
func (s *Store) LogoutDevice(ctx context.Context, deviceID string, now time.Time) error {
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		return revokeDevice(ctx, tx, deviceID, now)
	})
	if err != nil {
		return fmt.Errorf("登出: %w", err)
	}
	return nil
}

// CreateRecoveryToken 保存恢复流程令牌摘要。
func (s *Store) CreateRecoveryToken(ctx context.Context, userID string, hash []byte, expiresAt time.Time) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO recovery_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, $3)`,
		hash, userID, expiresAt)
	if err != nil {
		return fmt.Errorf("保存恢复令牌: %w", err)
	}
	return nil
}

// FinishRecovery 消费恢复令牌:替换主密码相关字段、关闭二次验证、吊销所有设备,并为当前设备建立新会话(协议 §4.1)。
// 令牌不存在、已用或过期时返回 ErrTokenInvalid。返回账号 ID。
func (s *Store) FinishRecovery(ctx context.Context, tokenHash []byte, upd PasswordUpdate, d NewDevice, r NewRefresh, now time.Time) (string, error) {
	var userID string
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var (
			expiresAt time.Time
			usedAt    *time.Time
		)
		err := tx.QueryRow(ctx, `SELECT user_id::text, expires_at, used_at FROM recovery_tokens
			WHERE token_hash = $1 FOR UPDATE`, tokenHash).Scan(&userID, &expiresAt, &usedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrTokenInvalid
		}
		if err != nil {
			return fmt.Errorf("查询恢复令牌: %w", err)
		}
		if usedAt != nil || !expiresAt.After(now) {
			return ErrTokenInvalid
		}
		// 同一账号其它未用的恢复令牌一并作废。
		if _, err := tx.Exec(ctx, `UPDATE recovery_tokens SET used_at = $2 WHERE user_id = $1 AND used_at IS NULL`,
			userID, now); err != nil {
			return fmt.Errorf("作废恢复令牌: %w", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET kdf = $2, auth_hash = $3, auth_salt = $4, encrypted_account_key = $5,
				totp_enabled = false, totp_secret_enc = NULL, totp_pending_enc = NULL, updated_at = $6
			WHERE id = $1`, userID, upd.KDF, upd.AuthHash, upd.AuthSalt, upd.EncryptedAccountKey, now); err != nil {
			return fmt.Errorf("替换主密码: %w", err)
		}
		if err := revokeDevices(ctx, tx, userID, "", now); err != nil {
			return err
		}
		if err := insertDevice(ctx, tx, userID, d); err != nil {
			return err
		}
		return insertRefresh(ctx, tx, d.ID, r)
	})
	if err != nil {
		if errors.Is(err, ErrTokenInvalid) {
			return "", err
		}
		return "", fmt.Errorf("完成恢复: %w", err)
	}
	return userID, nil
}
