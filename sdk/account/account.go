// Package account 实现高层账号流程(sync-protocol §2.1、§4.1):
// 注册、登录、用恢复码重置主密码、修改主密码、开关二次验证。
//
// 所有流程都在本机完成密钥派生与包装,服务器只拿到 authKey / recoveryAuthKey 与密文。
// 成功后返回解锁的 crypto.Keys,交给 engine 使用;令牌由 api.Client 持有并通过其 OnTokens 回调持久化。
package account

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/ComeHereToSee/typoza-backend/sdk/api"
	"github.com/ComeHereToSee/typoza-backend/sdk/crypto"
)

// ErrEmptyPassword 表示主密码为空。
var ErrEmptyPassword = errors.New("account: 主密码不能为空")

// ErrEmptyEmail 表示邮箱为空。
var ErrEmptyEmail = errors.New("account: 邮箱不能为空")

// Session 是解锁后的账号会话。
type Session struct {
	UserID   string
	DeviceID string
	// Keys 是解锁后的数据密钥,只存在内存里;宿主如需「记住登录」应自行放进钥匙串。
	Keys *crypto.Keys
}

// Registration 是注册结果。
type Registration struct {
	Session
	// RecoveryCode 是恢复码(13 组、每组 4 字符),只在注册时出现这一次,
	// 必须展示给用户抄下;丢失主密码与恢复码 = 云端数据不可解。
	RecoveryCode string
}

// NormalizeEmail 按协议规范化邮箱:trim + 小写。
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func toAPIKDF(p crypto.KDFParams) api.KDF {
	return api.KDF{
		Algorithm:   "argon2id",
		MemoryKiB:   p.MemoryKiB,
		Iterations:  p.Iterations,
		Parallelism: uint32(p.Parallelism),
		Salt:        p.Salt,
	}
}

// fromAPIKDF 转换并校验服务器下发的 KDF 参数;拒绝弱参数,防止服务器借此离线爆破主密码。
func fromAPIKDF(k api.KDF) (crypto.KDFParams, error) {
	if k.Algorithm != "argon2id" {
		return crypto.KDFParams{}, fmt.Errorf("account: 不支持的 KDF 算法 %q", k.Algorithm)
	}
	if k.Parallelism < crypto.MinParallelism || k.Parallelism > crypto.MaxParallelism {
		return crypto.KDFParams{}, fmt.Errorf("%w: parallelism=%d", crypto.ErrWeakKDF, k.Parallelism)
	}
	p := crypto.KDFParams{
		MemoryKiB:   k.MemoryKiB,
		Iterations:  k.Iterations,
		Parallelism: uint8(k.Parallelism),
		Salt:        k.Salt,
	}
	if err := p.Validate(); err != nil {
		return crypto.KDFParams{}, err
	}
	return p, nil
}

func checkCredentials(email, password string) error {
	if email == "" {
		return ErrEmptyEmail
	}
	if password == "" {
		return ErrEmptyPassword
	}
	return nil
}

// Register 注册新账号:本机生成盐、accountKey 与 recoveryKey,派生并包装后提交。
// 成功后 c 持有新会话令牌;返回的 RecoveryCode 必须展示给用户。
func Register(ctx context.Context, c *api.Client, email, password string, device api.Device) (*Registration, error) {
	email = NormalizeEmail(email)
	if err := checkCredentials(email, password); err != nil {
		return nil, err
	}
	kdf := crypto.DefaultKDF()
	mk, err := crypto.DeriveMasterKey(password, kdf)
	if err != nil {
		return nil, fmt.Errorf("account: 派生主密钥: %w", err)
	}
	ak := crypto.NewAccountKey()
	eak, err := crypto.WrapAccountKey(mk.WrapKey(), ak)
	if err != nil {
		return nil, fmt.Errorf("account: 包装账户密钥: %w", err)
	}
	rk := crypto.NewRecoveryKey()
	reak, err := crypto.WrapAccountKeyForRecovery(rk.WrapKey(), ak)
	if err != nil {
		return nil, fmt.Errorf("account: 用恢复密钥包装账户密钥: %w", err)
	}
	authKey := mk.AuthKey()
	recAuthKey := rk.AuthKey()
	sess, err := c.Register(ctx, api.RegisterRequest{
		Email:                       email,
		KDF:                         toAPIKDF(kdf),
		AuthKey:                     authKey[:],
		EncryptedAccountKey:         eak,
		RecoveryAuthKey:             recAuthKey[:],
		RecoveryEncryptedAccountKey: reak,
		Device:                      device,
	})
	if err != nil {
		return nil, fmt.Errorf("account: 注册: %w", err)
	}
	return &Registration{
		Session:      Session{UserID: sess.UserID, DeviceID: sess.DeviceID, Keys: crypto.DeriveKeys(ak)},
		RecoveryCode: crypto.FormatRecoveryCode(rk),
	}, nil
}

// LoginOptions 是登录的可选参数。
type LoginOptions struct {
	// TOTPCode 是二次验证码;账号开启二次验证而未提供时返回 api 错误码 totp_required。
	TOTPCode string
	// DeviceID 是本机上次登录得到的设备 ID;提供时服务器复用该设备记录。
	DeviceID string
	// Device 是设备名称与平台。
	Device api.Device
}

// Login 登录:prelogin 取 KDF 参数 → 派生 → login → 用 wrapKey 解开 accountKey。
// 密码错误时返回 api 错误码 unauthorized(用 api.IsCode 判断)。
func Login(ctx context.Context, c *api.Client, email, password string, opts LoginOptions) (*Session, error) {
	email = NormalizeEmail(email)
	if err := checkCredentials(email, password); err != nil {
		return nil, err
	}
	mk, err := deriveForAccount(ctx, c, email, password)
	if err != nil {
		return nil, err
	}
	authKey := mk.AuthKey()
	sess, err := c.Login(ctx, api.LoginRequest{
		Email:    email,
		AuthKey:  authKey[:],
		TOTPCode: opts.TOTPCode,
		Device:   opts.Device,
		DeviceID: opts.DeviceID,
	})
	if err != nil {
		return nil, fmt.Errorf("account: 登录: %w", err)
	}
	ak, err := crypto.UnwrapAccountKey(mk.WrapKey(), sess.EncryptedAccountKey)
	if err != nil {
		return nil, fmt.Errorf("account: 登录成功但解不开账户密钥(服务器返回的数据异常): %w", err)
	}
	return &Session{UserID: sess.UserID, DeviceID: sess.DeviceID, Keys: crypto.DeriveKeys(ak)}, nil
}

// deriveForAccount 取账号当前 KDF 参数并派生 MasterKey。
func deriveForAccount(ctx context.Context, c *api.Client, email, password string) (crypto.MasterKey, error) {
	kdf, err := c.Prelogin(ctx, email)
	if err != nil {
		return crypto.MasterKey{}, fmt.Errorf("account: 获取 KDF 参数: %w", err)
	}
	params, err := fromAPIKDF(kdf)
	if err != nil {
		return crypto.MasterKey{}, fmt.Errorf("account: 服务器下发的 KDF 参数不可接受: %w", err)
	}
	mk, err := crypto.DeriveMasterKey(password, params)
	if err != nil {
		return crypto.MasterKey{}, fmt.Errorf("account: 派生主密钥: %w", err)
	}
	return mk, nil
}

// Recover 用恢复码重置主密码:recover/begin 换回 recoveryEncryptedAccountKey → 解开 accountKey →
// 用新主密码重新派生、包装 → recover/finish。服务器会关闭二次验证并吊销所有设备令牌;
// 恢复码本身不变。成功后 c 持有新会话令牌。
func Recover(ctx context.Context, c *api.Client, email, recoveryCode, newPassword string, device api.Device) (*Session, error) {
	email = NormalizeEmail(email)
	if err := checkCredentials(email, newPassword); err != nil {
		return nil, err
	}
	rk, err := crypto.ParseRecoveryCode(recoveryCode)
	if err != nil {
		return nil, err
	}
	recAuthKey := rk.AuthKey()
	begin, err := c.RecoverBegin(ctx, email, recAuthKey[:])
	if err != nil {
		return nil, fmt.Errorf("account: 开始恢复: %w", err)
	}
	ak, err := crypto.UnwrapAccountKeyForRecovery(rk.WrapKey(), begin.RecoveryEncryptedAccountKey)
	if err != nil {
		return nil, fmt.Errorf("account: 用恢复码解开账户密钥: %w", err)
	}
	kdf := crypto.DefaultKDF()
	mk, err := crypto.DeriveMasterKey(newPassword, kdf)
	if err != nil {
		return nil, fmt.Errorf("account: 派生新主密钥: %w", err)
	}
	eak, err := crypto.WrapAccountKey(mk.WrapKey(), ak)
	if err != nil {
		return nil, fmt.Errorf("account: 包装账户密钥: %w", err)
	}
	authKey := mk.AuthKey()
	sess, err := c.RecoverFinish(ctx, api.RecoverFinishRequest{
		RecoveryToken:       begin.RecoveryToken,
		KDF:                 toAPIKDF(kdf),
		AuthKey:             authKey[:],
		EncryptedAccountKey: eak,
		Device:              device,
	})
	if err != nil {
		return nil, fmt.Errorf("account: 完成恢复: %w", err)
	}
	return &Session{UserID: sess.UserID, DeviceID: sess.DeviceID, Keys: crypto.DeriveKeys(ak)}, nil
}

// ChangePassword 修改主密码:只用新盐与新主密码重新包装 accountKey,数据不重加密。
// keys 是当前已解锁的密钥(来自 Login/Register/Recover)。服务器会吊销除当前设备外的所有设备令牌。
func ChangePassword(ctx context.Context, c *api.Client, email, oldPassword, newPassword string, keys *crypto.Keys) error {
	email = NormalizeEmail(email)
	if err := checkCredentials(email, newPassword); err != nil {
		return err
	}
	if oldPassword == "" {
		return ErrEmptyPassword
	}
	if keys == nil {
		return errors.New("account: 修改主密码需要已解锁的密钥")
	}
	oldMK, err := deriveForAccount(ctx, c, email, oldPassword)
	if err != nil {
		return err
	}
	newKDF := crypto.DefaultKDF()
	newMK, err := crypto.DeriveMasterKey(newPassword, newKDF)
	if err != nil {
		return fmt.Errorf("account: 派生新主密钥: %w", err)
	}
	eak, err := crypto.WrapAccountKey(newMK.WrapKey(), keys.Account)
	if err != nil {
		return fmt.Errorf("account: 包装账户密钥: %w", err)
	}
	oldAuth := oldMK.AuthKey()
	newAuth := newMK.AuthKey()
	if err := c.ChangePassword(ctx, api.ChangePasswordRequest{
		AuthKey:                oldAuth[:],
		NewKDF:                 toAPIKDF(newKDF),
		NewAuthKey:             newAuth[:],
		NewEncryptedAccountKey: eak,
	}); err != nil {
		return fmt.Errorf("account: 修改主密码: %w", err)
	}
	return nil
}

// SetupTOTP 生成二次验证密钥(未启用前可重复调用,覆盖旧密钥)。宿主用返回的 otpauth URL 生成二维码。
func SetupTOTP(ctx context.Context, c *api.Client) (*api.TOTPSetup, error) {
	s, err := c.TOTPSetup(ctx)
	if err != nil {
		return nil, fmt.Errorf("account: 生成二次验证密钥: %w", err)
	}
	return s, nil
}

// EnableTOTP 用验证器上的当前验证码启用二次验证。
func EnableTOTP(ctx context.Context, c *api.Client, code string) error {
	if err := c.TOTPEnable(ctx, code); err != nil {
		return fmt.Errorf("account: 启用二次验证: %w", err)
	}
	return nil
}

// DisableTOTP 用验证器上的当前验证码关闭二次验证。
func DisableTOTP(ctx context.Context, c *api.Client, code string) error {
	if err := c.TOTPDisable(ctx, code); err != nil {
		return fmt.Errorf("account: 关闭二次验证: %w", err)
	}
	return nil
}
