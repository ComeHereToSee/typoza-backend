package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// User 是账号记录。
type User struct {
	ID                          string
	Email                       string
	KDF                         []byte // jsonb 原文
	AuthHash                    []byte
	AuthSalt                    []byte
	EncryptedAccountKey         string
	RecoveryAuthHash            []byte
	RecoveryAuthSalt            []byte
	RecoveryEncryptedAccountKey string
	TOTPSecretEnc               []byte
	TOTPPendingEnc              []byte
	TOTPEnabled                 bool
	TOTPLastStep                int64
	QuotaBytes                  int64
	UsedBytes                   int64
	CreatedAt                   time.Time
}

const userColumns = `id::text, email, kdf, auth_hash, auth_salt, encrypted_account_key,
	recovery_auth_hash, recovery_auth_salt, recovery_encrypted_account_key,
	totp_secret_enc, totp_pending_enc, totp_enabled, totp_last_step, quota_bytes, used_bytes, created_at`

func scanUser(row pgx.Row) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Email, &u.KDF, &u.AuthHash, &u.AuthSalt, &u.EncryptedAccountKey,
		&u.RecoveryAuthHash, &u.RecoveryAuthSalt, &u.RecoveryEncryptedAccountKey,
		&u.TOTPSecretEnc, &u.TOTPPendingEnc, &u.TOTPEnabled, &u.TOTPLastStep, &u.QuotaBytes, &u.UsedBytes, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("读取账号: %w", err)
	}
	u.CreatedAt = utc(u.CreatedAt)
	return u, nil
}

// NewUser 是注册时写入的账号字段。
type NewUser struct {
	ID                          string
	Email                       string
	KDF                         []byte
	AuthHash                    []byte
	AuthSalt                    []byte
	EncryptedAccountKey         string
	RecoveryAuthHash            []byte
	RecoveryAuthSalt            []byte
	RecoveryEncryptedAccountKey string
	QuotaBytes                  int64
}

// NewDevice 是新设备记录。
type NewDevice struct {
	ID       string
	Name     string
	Platform string
}

// NewRefresh 是新刷新令牌记录(只含摘要)。
type NewRefresh struct {
	ID        string
	FamilyID  string
	Hash      []byte
	ExpiresAt time.Time
	// ParentID 是换出它的旧令牌;登录、注册、恢复时为空。
	ParentID string
}

// PasswordUpdate 是改密与恢复时替换的主密码相关字段。
type PasswordUpdate struct {
	KDF                 []byte
	AuthHash            []byte
	AuthSalt            []byte
	EncryptedAccountKey string
}

// CreateUser 在一个事务里创建账号、首个设备与首个刷新令牌。
func (s *Store) CreateUser(ctx context.Context, u NewUser, d NewDevice, r NewRefresh) error {
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO users (id, email, kdf, auth_hash, auth_salt, encrypted_account_key,
				recovery_auth_hash, recovery_auth_salt, recovery_encrypted_account_key, quota_bytes)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			u.ID, u.Email, u.KDF, u.AuthHash, u.AuthSalt, u.EncryptedAccountKey,
			u.RecoveryAuthHash, u.RecoveryAuthSalt, u.RecoveryEncryptedAccountKey, u.QuotaBytes)
		if err != nil {
			return err
		}
		if err := insertDevice(ctx, tx, u.ID, d); err != nil {
			return err
		}
		return insertRefresh(ctx, tx, d.ID, r)
	})
	if isUniqueViolation(err, "users_email_key") {
		return ErrEmailTaken
	}
	if err != nil {
		return fmt.Errorf("创建账号: %w", err)
	}
	return nil
}

// UserByEmail 按规范化邮箱查账号。
func (s *Store) UserByEmail(ctx context.Context, email string) (User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE email = $1`, email))
}

// UserByID 按 ID 查账号。
func (s *Store) UserByID(ctx context.Context, id string) (User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE id = $1`, id))
}

// UpdatePassword 替换主密码相关字段,并吊销除 keepDeviceID 外的所有设备(协议 §4.1 改密)。
func (s *Store) UpdatePassword(ctx context.Context, userID string, upd PasswordUpdate, keepDeviceID string, now time.Time) error {
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE users SET kdf = $2, auth_hash = $3, auth_salt = $4,
				encrypted_account_key = $5, updated_at = $6
			WHERE id = $1`,
			userID, upd.KDF, upd.AuthHash, upd.AuthSalt, upd.EncryptedAccountKey, now)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return revokeDevices(ctx, tx, userID, keepDeviceID, now)
	})
	if errors.Is(err, ErrNotFound) {
		return err
	}
	if err != nil {
		return fmt.Errorf("修改主密码: %w", err)
	}
	return nil
}

// DeleteUser 删除账号及其全部数据(外键级联),返回需要从对象存储删除的对象键。
func (s *Store) DeleteUser(ctx context.Context, userID string) ([]string, error) {
	var keys []string
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		// 先锁住账号行,防止删除期间并发上传新块漏掉对象键。
		var id string
		if err := tx.QueryRow(ctx, `SELECT id::text FROM users WHERE id = $1 FOR UPDATE`, userID).Scan(&id); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		rows, err := tx.Query(ctx, `SELECT object_key FROM chunks WHERE user_id = $1`, userID)
		if err != nil {
			return err
		}
		keys, err = pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
		return err
	})
	if errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("删除账号: %w", err)
	}
	return keys, nil
}

// SetTOTPPending 保存待确认的 TOTP 密钥(覆盖旧的);已启用时返回 false。
func (s *Store) SetTOTPPending(ctx context.Context, userID string, enc []byte, now time.Time) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE users SET totp_pending_enc = $2, updated_at = $3
		WHERE id = $1 AND NOT totp_enabled`, userID, enc, now)
	if err != nil {
		return false, fmt.Errorf("保存待确认 TOTP 密钥: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// EnableTOTP 把待确认密钥转正。pendingEnc 必须与校验时读到的一致,防止与并发的 setup 交错。
func (s *Store) EnableTOTP(ctx context.Context, userID string, pendingEnc []byte, step int64, now time.Time) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE users SET totp_secret_enc = totp_pending_enc, totp_pending_enc = NULL,
			totp_enabled = true, totp_last_step = $3, updated_at = $4
		WHERE id = $1 AND NOT totp_enabled AND totp_pending_enc = $2`, userID, pendingEnc, step, now)
	if err != nil {
		return false, fmt.Errorf("启用 TOTP: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// ConsumeTOTPStep 原子地把 totp_last_step 推进到 step;step 不大于已用步长时返回 false(重放)。
func (s *Store) ConsumeTOTPStep(ctx context.Context, userID string, step int64) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE users SET totp_last_step = $2
		WHERE id = $1 AND totp_enabled AND totp_last_step < $2`, userID, step)
	if err != nil {
		return false, fmt.Errorf("记录 TOTP 步长: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// DisableTOTP 关闭二次验证,同时消费本次验证码的步长。
func (s *Store) DisableTOTP(ctx context.Context, userID string, step int64, now time.Time) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE users SET totp_enabled = false, totp_secret_enc = NULL, totp_pending_enc = NULL,
			totp_last_step = $2, updated_at = $3
		WHERE id = $1 AND totp_enabled AND totp_last_step < $2`, userID, step, now)
	if err != nil {
		return false, fmt.Errorf("关闭 TOTP: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// Audit 记录一条安全审计事件。
func (s *Store) Audit(ctx context.Context, userID, deviceID, kind, ip string) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO audit_events (user_id, device_id, kind, ip) VALUES ($1, $2, $3, $4)`,
		userID, nullable(deviceID), kind, ip)
	if err != nil {
		return fmt.Errorf("写审计事件 %s: %w", kind, err)
	}
	return nil
}
