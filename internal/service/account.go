package service

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/ComeHereToSee/typoza-backend/internal/apierr"
	"github.com/ComeHereToSee/typoza-backend/internal/auth"
	"github.com/ComeHereToSee/typoza-backend/internal/ids"
	"github.com/ComeHereToSee/typoza-backend/internal/store"
)

// Prelogin 返回邮箱对应的 KDF 参数。未注册邮箱返回确定性的假参数:
// 盐 = HMAC-SHA256(枚举密钥, 规范化邮箱) 前 16 字节、参数为默认值(协议 §4.1),
// 同一邮箱每次结果相同,外人无法据此判断邮箱是否注册。
func (s *Service) Prelogin(ctx context.Context, email string) (KDF, error) {
	u, err := s.store.UserByEmail(ctx, email)
	if errors.Is(err, store.ErrNotFound) {
		return FakeKDF(s.enumSecret, email), nil
	}
	if err != nil {
		return KDF{}, err
	}
	return parseKDF(u.KDF)
}

// FakeKDF 计算未注册邮箱的假 KDF 参数(导出供测试核对)。
func FakeKDF(enumSecret []byte, email string) KDF {
	mac := hmac.New(sha256.New, enumSecret)
	mac.Write([]byte(email))
	return defaultKDF(mac.Sum(nil)[:kdfSaltLen])
}

// RegisterInput 是注册请求(已通过边界校验)。
type RegisterInput struct {
	Email                       string
	KDF                         KDF
	AuthKey                     []byte
	EncryptedAccountKey         string
	RecoveryAuthKey             []byte
	RecoveryEncryptedAccountKey string
	Device                      DeviceInfo
	IP                          string
}

// Register 创建账号与首个设备会话。
func (s *Service) Register(ctx context.Context, in RegisterInput) (Session, error) {
	if !s.registrationOpen {
		return Session{}, errRegistrationClosed
	}
	// 先做便宜的查重,避免对已注册邮箱白算两次 Argon2;并发注册由唯一约束兜住。
	if _, err := s.store.UserByEmail(ctx, in.Email); err == nil {
		return Session{}, errEmailTaken
	} else if !errors.Is(err, store.ErrNotFound) {
		return Session{}, err
	}
	kdfJSON, err := marshalKDF(in.KDF)
	if err != nil {
		return Session{}, err
	}
	authSalt, recoverySalt := auth.NewSalt(), auth.NewSalt()
	authHash, err := s.hasher.Hash(ctx, in.AuthKey, authSalt)
	if err != nil {
		return Session{}, err
	}
	recoveryHash, err := s.hasher.Hash(ctx, in.RecoveryAuthKey, recoverySalt)
	if err != nil {
		return Session{}, err
	}

	now := s.now()
	userID, deviceID := ids.New(), ids.New()
	refreshPlain, refreshHash := auth.NewOpaque(auth.RefreshPrefix)
	err = s.store.CreateUser(ctx, store.NewUser{
		ID:                          userID,
		Email:                       in.Email,
		KDF:                         kdfJSON,
		AuthHash:                    authHash,
		AuthSalt:                    authSalt,
		EncryptedAccountKey:         in.EncryptedAccountKey,
		RecoveryAuthHash:            recoveryHash,
		RecoveryAuthSalt:            recoverySalt,
		RecoveryEncryptedAccountKey: in.RecoveryEncryptedAccountKey,
		QuotaBytes:                  s.quota,
	}, store.NewDevice{ID: deviceID, Name: in.Device.Name, Platform: in.Device.Platform},
		newRefresh(refreshHash, now))
	if errors.Is(err, store.ErrEmailTaken) {
		return Session{}, errEmailTaken
	}
	if err != nil {
		return Session{}, err
	}
	access, err := s.signer.Issue(userID, deviceID, now)
	if err != nil {
		return Session{}, err
	}
	if err := s.audit(ctx, userID, deviceID, auditRegistered, in.IP); err != nil {
		return Session{}, err
	}
	return Session{
		UserID:               userID,
		DeviceID:             deviceID,
		AccessToken:          access,
		AccessTokenExpiresIn: accessTTLSeconds,
		RefreshToken:         refreshPlain,
		EncryptedAccountKey:  in.EncryptedAccountKey,
		KDF:                  in.KDF,
	}, nil
}

func newRefresh(hash []byte, now time.Time) store.NewRefresh {
	return store.NewRefresh{ID: ids.New(), FamilyID: ids.New(), Hash: hash, ExpiresAt: now.Add(auth.RefreshTTL)}
}

// LoginInput 是登录请求。
type LoginInput struct {
	Email    string
	AuthKey  []byte
	TOTPCode string
	Device   DeviceInfo
	DeviceID string // 可空:带上且属于该账号时复用设备记录
	IP       string
}

// Login 校验口令(与可选的二次验证)并建立会话。
func (s *Service) Login(ctx context.Context, in LoginInput) (Session, error) {
	u, err := s.verifyAuthKey(ctx, in.Email, in.AuthKey, false)
	if err != nil {
		if errors.Is(err, errBadCredentials) {
			if u.ID != "" {
				if auditErr := s.audit(ctx, u.ID, "", auditLoginFailed, in.IP); auditErr != nil {
					return Session{}, auditErr
				}
			}
			return Session{}, apierr.Unauthorized()
		}
		return Session{}, err
	}
	if u.TOTPEnabled {
		if in.TOTPCode == "" {
			return Session{}, errTOTPRequired
		}
		if err := s.consumeTOTP(ctx, u, in.TOTPCode); err != nil {
			if errors.Is(err, errTOTPInvalid) {
				if auditErr := s.audit(ctx, u.ID, "", auditLoginFailed, in.IP); auditErr != nil {
					return Session{}, auditErr
				}
			}
			return Session{}, err
		}
	}

	now := s.now()
	refreshPlain, refreshHash := auth.NewOpaque(auth.RefreshPrefix)
	deviceID, err := s.store.LoginDevice(ctx, u.ID, in.DeviceID,
		store.NewDevice{ID: ids.New(), Name: in.Device.Name, Platform: in.Device.Platform},
		newRefresh(refreshHash, now), now)
	if err != nil {
		return Session{}, err
	}
	access, err := s.signer.Issue(u.ID, deviceID, now)
	if err != nil {
		return Session{}, err
	}
	kdf, err := parseKDF(u.KDF)
	if err != nil {
		return Session{}, err
	}
	if err := s.audit(ctx, u.ID, deviceID, auditLoginSucceeded, in.IP); err != nil {
		return Session{}, err
	}
	return Session{
		UserID:               u.ID,
		DeviceID:             deviceID,
		AccessToken:          access,
		AccessTokenExpiresIn: accessTTLSeconds,
		RefreshToken:         refreshPlain,
		EncryptedAccountKey:  u.EncryptedAccountKey,
		KDF:                  kdf,
	}, nil
}

// errBadCredentials 是内部哨兵:邮箱不存在或口令不符,对外统一为 401 unauthorized(不区分是哪项)。
var errBadCredentials = errors.New("账号或口令错误")

// verifyAuthKey 按邮箱查账号并校验 authKey(recovery 为 true 时校验恢复口令)。
// 邮箱不存在时也算一次 Argon2,使响应时间与「口令错误」一致,防止靠时延探测邮箱是否注册。
// 口令错误时返回的 User 带有 ID(用于审计),邮箱不存在时为零值。
func (s *Service) verifyAuthKey(ctx context.Context, email string, key []byte, recovery bool) (store.User, error) {
	u, err := s.store.UserByEmail(ctx, email)
	if errors.Is(err, store.ErrNotFound) {
		if _, err := s.hasher.Hash(ctx, key, s.dummySalt); err != nil {
			return store.User{}, err
		}
		return store.User{}, errBadCredentials
	}
	if err != nil {
		return store.User{}, err
	}
	salt, hash := u.AuthSalt, u.AuthHash
	if recovery {
		salt, hash = u.RecoveryAuthSalt, u.RecoveryAuthHash
	}
	ok, err := s.hasher.Verify(ctx, key, salt, hash)
	if err != nil {
		return store.User{}, err
	}
	if !ok {
		return store.User{ID: u.ID}, errBadCredentials
	}
	return u, nil
}

// verifyOwnAuthKey 校验已登录账号的当前 authKey(改密、删号前的二次确认)。
func (s *Service) verifyOwnAuthKey(ctx context.Context, userID string, key []byte) (store.User, error) {
	u, err := s.store.UserByID(ctx, userID)
	if errors.Is(err, store.ErrNotFound) {
		return store.User{}, apierr.Unauthorized()
	}
	if err != nil {
		return store.User{}, err
	}
	ok, err := s.hasher.Verify(ctx, key, u.AuthSalt, u.AuthHash)
	if err != nil {
		return store.User{}, err
	}
	if !ok {
		return store.User{}, apierr.Unauthorized()
	}
	return u, nil
}

// consumeTOTP 校验已启用的二次验证码并原子消费其步长。
func (s *Service) consumeTOTP(ctx context.Context, u store.User, code string) error {
	secret, err := s.box.Open(u.TOTPSecretEnc, totpAAD(u.ID))
	if err != nil {
		return err
	}
	step, ok := auth.VerifyTOTP(secret, code, s.now(), u.TOTPLastStep)
	if !ok {
		return errTOTPInvalid
	}
	consumed, err := s.store.ConsumeTOTPStep(ctx, u.ID, step)
	if err != nil {
		return err
	}
	if !consumed {
		// 并发请求抢先用掉了同一步长(或更新的步长)。
		return errTOTPInvalid
	}
	return nil
}

// Refresh 轮换刷新令牌并签发新访问令牌。
func (s *Service) Refresh(ctx context.Context, token, ip string) (Tokens, error) {
	if !auth.ValidOpaque(auth.RefreshPrefix, token) {
		return Tokens{}, apierr.Unauthorized()
	}
	now := s.now()
	plain, hash := auth.NewOpaque(auth.RefreshPrefix)
	userID, deviceID, err := s.store.RotateRefresh(ctx, auth.Digest(token), newRefresh(hash, now), now)
	switch {
	case errors.Is(err, store.ErrTokenInvalid):
		return Tokens{}, apierr.Unauthorized()
	case errors.Is(err, store.ErrRefreshReuse):
		s.log.Warn("检测到刷新令牌重放,已吊销设备令牌链", "userId", userID, "deviceId", deviceID)
		if auditErr := s.audit(ctx, userID, deviceID, auditRefreshReuse, ip); auditErr != nil {
			return Tokens{}, auditErr
		}
		return Tokens{}, errRefreshReuse
	case err != nil:
		return Tokens{}, err
	}
	access, err := s.signer.Issue(userID, deviceID, now)
	if err != nil {
		return Tokens{}, err
	}
	return Tokens{AccessToken: access, AccessTokenExpiresIn: accessTTLSeconds, RefreshToken: plain}, nil
}

// Logout 吊销当前设备的令牌链。
func (s *Service) Logout(ctx context.Context, p Principal) error {
	return s.store.LogoutDevice(ctx, p.DeviceID, s.now())
}

// Authenticate 校验访问令牌,并确认设备仍处于登录状态。
func (s *Service) Authenticate(ctx context.Context, token, ip string) (Principal, error) {
	now := s.now()
	userID, deviceID, err := s.signer.Verify(token, now)
	if errors.Is(err, auth.ErrAccessExpired) {
		return Principal{}, apierr.TokenExpired()
	}
	if err != nil {
		return Principal{}, apierr.Unauthorized()
	}
	active, err := s.store.TouchDevice(ctx, userID, deviceID, now)
	if err != nil {
		return Principal{}, err
	}
	if !active {
		return Principal{}, apierr.Unauthorized()
	}
	return Principal{UserID: userID, DeviceID: deviceID, IP: ip}, nil
}

// DeviceActive 供长连接定期确认设备未被吊销。
func (s *Service) DeviceActive(ctx context.Context, p Principal) (bool, error) {
	return s.store.TouchDevice(ctx, p.UserID, p.DeviceID, s.now())
}

// RecoverBegin 校验恢复口令并发放一次性恢复令牌。
func (s *Service) RecoverBegin(ctx context.Context, email string, recoveryAuthKey []byte, ip string) (RecoveryStart, error) {
	u, err := s.verifyAuthKey(ctx, email, recoveryAuthKey, true)
	if err != nil {
		if errors.Is(err, errBadCredentials) {
			if u.ID != "" {
				if auditErr := s.audit(ctx, u.ID, "", auditRecoveryFailed, ip); auditErr != nil {
					return RecoveryStart{}, auditErr
				}
			}
			return RecoveryStart{}, apierr.Unauthorized()
		}
		return RecoveryStart{}, err
	}
	plain, hash := auth.NewOpaque(auth.RecoveryPrefix)
	if err := s.store.CreateRecoveryToken(ctx, u.ID, hash, s.now().Add(auth.RecoveryTTL)); err != nil {
		return RecoveryStart{}, err
	}
	if err := s.audit(ctx, u.ID, "", auditRecoveryStarted, ip); err != nil {
		return RecoveryStart{}, err
	}
	return RecoveryStart{RecoveryEncryptedAccountKey: u.RecoveryEncryptedAccountKey, RecoveryToken: plain}, nil
}

// RecoverFinishInput 是 recover/finish 请求。
type RecoverFinishInput struct {
	RecoveryToken       string
	KDF                 KDF
	AuthKey             []byte
	EncryptedAccountKey string
	Device              DeviceInfo
	IP                  string
}

// RecoverFinish 用恢复令牌重置主密码:替换主密码相关字段、关闭二次验证、吊销所有设备,并为当前设备建立会话。
func (s *Service) RecoverFinish(ctx context.Context, in RecoverFinishInput) (Session, error) {
	if !auth.ValidOpaque(auth.RecoveryPrefix, in.RecoveryToken) {
		return Session{}, apierr.Unauthorized()
	}
	kdfJSON, err := marshalKDF(in.KDF)
	if err != nil {
		return Session{}, err
	}
	salt := auth.NewSalt()
	hash, err := s.hasher.Hash(ctx, in.AuthKey, salt)
	if err != nil {
		return Session{}, err
	}
	now := s.now()
	deviceID := ids.New()
	refreshPlain, refreshHash := auth.NewOpaque(auth.RefreshPrefix)
	userID, err := s.store.FinishRecovery(ctx, auth.Digest(in.RecoveryToken),
		store.PasswordUpdate{KDF: kdfJSON, AuthHash: hash, AuthSalt: salt, EncryptedAccountKey: in.EncryptedAccountKey},
		store.NewDevice{ID: deviceID, Name: in.Device.Name, Platform: in.Device.Platform},
		newRefresh(refreshHash, now), now)
	if errors.Is(err, store.ErrTokenInvalid) {
		return Session{}, apierr.Unauthorized()
	}
	if err != nil {
		return Session{}, err
	}
	access, err := s.signer.Issue(userID, deviceID, now)
	if err != nil {
		return Session{}, err
	}
	if err := s.audit(ctx, userID, deviceID, auditRecoveryFinished, in.IP); err != nil {
		return Session{}, err
	}
	return Session{
		UserID:               userID,
		DeviceID:             deviceID,
		AccessToken:          access,
		AccessTokenExpiresIn: accessTTLSeconds,
		RefreshToken:         refreshPlain,
		EncryptedAccountKey:  in.EncryptedAccountKey,
		KDF:                  in.KDF,
	}, nil
}

// Account 返回账号信息与用量。
func (s *Service) Account(ctx context.Context, p Principal) (Account, error) {
	u, err := s.store.UserByID(ctx, p.UserID)
	if errors.Is(err, store.ErrNotFound) {
		return Account{}, apierr.Unauthorized()
	}
	if err != nil {
		return Account{}, err
	}
	return Account{
		UserID:      u.ID,
		Email:       u.Email,
		TOTPEnabled: u.TOTPEnabled,
		CreatedAt:   formatTime(u.CreatedAt),
		Usage:       Usage{UsedBytes: u.UsedBytes, QuotaBytes: u.QuotaBytes},
	}, nil
}

// ChangePasswordInput 是改密请求。
type ChangePasswordInput struct {
	AuthKey                []byte
	NewKDF                 KDF
	NewAuthKey             []byte
	NewEncryptedAccountKey string
}

// ChangePassword 校验当前 authKey 后替换主密码相关字段,吊销除当前设备外的所有设备。
func (s *Service) ChangePassword(ctx context.Context, p Principal, in ChangePasswordInput) error {
	if _, err := s.verifyOwnAuthKey(ctx, p.UserID, in.AuthKey); err != nil {
		return err
	}
	kdfJSON, err := marshalKDF(in.NewKDF)
	if err != nil {
		return err
	}
	salt := auth.NewSalt()
	hash, err := s.hasher.Hash(ctx, in.NewAuthKey, salt)
	if err != nil {
		return err
	}
	err = s.store.UpdatePassword(ctx, p.UserID,
		store.PasswordUpdate{KDF: kdfJSON, AuthHash: hash, AuthSalt: salt, EncryptedAccountKey: in.NewEncryptedAccountKey},
		p.DeviceID, s.now())
	if errors.Is(err, store.ErrNotFound) {
		return apierr.Unauthorized()
	}
	if err != nil {
		return err
	}
	return s.audit(ctx, p.UserID, p.DeviceID, auditPasswordChanged, p.IP)
}

// DeleteAccount 校验 authKey 后删除账号与全部数据(块、清单、设备)。
func (s *Service) DeleteAccount(ctx context.Context, p Principal, authKey []byte) error {
	if _, err := s.verifyOwnAuthKey(ctx, p.UserID, authKey); err != nil {
		return err
	}
	keys, err := s.store.DeleteUser(ctx, p.UserID)
	if errors.Is(err, store.ErrNotFound) {
		return apierr.Unauthorized()
	}
	if err != nil {
		return err
	}
	s.deleteObjects(ctx, keys)
	s.log.Info("账号已删除", "userId", p.UserID, "objects", len(keys))
	return nil
}

var (
	errTOTPAlreadyEnabled = apierr.InvalidRequest("二次验证已启用,如需更换请先关闭")
	errTOTPNotPending     = apierr.InvalidRequest("请先调用 totp/setup 获取密钥")
	errTOTPNotEnabled     = apierr.InvalidRequest("二次验证未启用")
)

// TOTPSetup 生成新的待确认 TOTP 密钥(未启用前可重复调用,覆盖旧密钥)。
func (s *Service) TOTPSetup(ctx context.Context, p Principal) (TOTPSetup, error) {
	u, err := s.store.UserByID(ctx, p.UserID)
	if err != nil {
		return TOTPSetup{}, err
	}
	if u.TOTPEnabled {
		return TOTPSetup{}, errTOTPAlreadyEnabled
	}
	secret := auth.NewTOTPSecret()
	ok, err := s.store.SetTOTPPending(ctx, u.ID, s.box.Seal(secret, totpAAD(u.ID)), s.now())
	if err != nil {
		return TOTPSetup{}, err
	}
	if !ok {
		return TOTPSetup{}, errTOTPAlreadyEnabled
	}
	return TOTPSetup{Secret: auth.EncodeTOTPSecret(secret), OtpauthURL: auth.TOTPURL(u.Email, secret)}, nil
}

// TOTPEnable 用待确认密钥的验证码确认并启用二次验证。
func (s *Service) TOTPEnable(ctx context.Context, p Principal, code string) error {
	u, err := s.store.UserByID(ctx, p.UserID)
	if err != nil {
		return err
	}
	if u.TOTPEnabled {
		return errTOTPAlreadyEnabled
	}
	if u.TOTPPendingEnc == nil {
		return errTOTPNotPending
	}
	secret, err := s.box.Open(u.TOTPPendingEnc, totpAAD(u.ID))
	if err != nil {
		return err
	}
	step, ok := auth.VerifyTOTP(secret, code, s.now(), u.TOTPLastStep)
	if !ok {
		return errTOTPInvalid
	}
	enabled, err := s.store.EnableTOTP(ctx, u.ID, u.TOTPPendingEnc, step, s.now())
	if err != nil {
		return err
	}
	if !enabled {
		return apierr.InvalidRequest("二次验证状态已变化,请重新 setup")
	}
	return s.audit(ctx, u.ID, p.DeviceID, auditTOTPEnabled, p.IP)
}

// TOTPDisable 用当前验证码关闭二次验证。
func (s *Service) TOTPDisable(ctx context.Context, p Principal, code string) error {
	u, err := s.store.UserByID(ctx, p.UserID)
	if err != nil {
		return err
	}
	if !u.TOTPEnabled {
		return errTOTPNotEnabled
	}
	secret, err := s.box.Open(u.TOTPSecretEnc, totpAAD(u.ID))
	if err != nil {
		return err
	}
	step, ok := auth.VerifyTOTP(secret, code, s.now(), u.TOTPLastStep)
	if !ok {
		return errTOTPInvalid
	}
	disabled, err := s.store.DisableTOTP(ctx, u.ID, step, s.now())
	if err != nil {
		return err
	}
	if !disabled {
		return errTOTPInvalid
	}
	return s.audit(ctx, u.ID, p.DeviceID, auditTOTPDisabled, p.IP)
}

// Devices 列出账号下已登录的设备。
func (s *Service) Devices(ctx context.Context, p Principal) ([]Device, error) {
	list, err := s.store.ListDevices(ctx, p.UserID)
	if err != nil {
		return nil, err
	}
	out := make([]Device, 0, len(list))
	for _, d := range list {
		out = append(out, Device{
			ID:         d.ID,
			Name:       d.Name,
			Platform:   d.Platform,
			CreatedAt:  formatTime(d.CreatedAt),
			LastSeenAt: formatTime(d.LastSeenAt),
			Current:    d.ID == p.DeviceID,
		})
	}
	return out, nil
}

// RevokeDevice 吊销账号下的某个设备。
func (s *Service) RevokeDevice(ctx context.Context, p Principal, deviceID string) error {
	err := s.store.RevokeDevice(ctx, p.UserID, deviceID, s.now())
	if errors.Is(err, store.ErrNotFound) {
		return apierr.NotFound("设备不存在")
	}
	if err != nil {
		return fmt.Errorf("吊销设备: %w", err)
	}
	return s.audit(ctx, p.UserID, deviceID, auditDeviceRevoked, p.IP)
}
