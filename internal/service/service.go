// Package service 是业务层:编排口令校验、令牌签发、TOTP、配额与块存储,把仓储错误翻译成协议错误码。
//
// 输入格式(UUID、base64url、长度)在 httpapi 边界已校验;这里只处理业务规则。
package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/ComeHereToSee/typoza-backend/internal/apierr"
	"github.com/ComeHereToSee/typoza-backend/internal/auth"
	"github.com/ComeHereToSee/typoza-backend/internal/blob"
	"github.com/ComeHereToSee/typoza-backend/internal/metrics"
	"github.com/ComeHereToSee/typoza-backend/internal/store"
)

// 审计事件类型。
const (
	auditRegistered       = "registered"
	auditLoginSucceeded   = "login_succeeded"
	auditLoginFailed      = "login_failed"
	auditRefreshReuse     = "refresh_reuse_detected"
	auditPasswordChanged  = "password_changed"
	auditRecoveryStarted  = "recovery_started"
	auditRecoveryFailed   = "recovery_failed"
	auditRecoveryFinished = "recovery_finished"
	auditDeviceRevoked    = "device_revoked"
	auditTOTPEnabled      = "totp_enabled"
	auditTOTPDisabled     = "totp_disabled"
)

// Options 是业务层依赖。
type Options struct {
	Store            *store.Store
	Blobs            blob.Store
	Hasher           *auth.Hasher
	Signer           *auth.Signer
	SecretBox        *auth.SecretBox
	EnumSecret       []byte
	RegistrationOpen bool
	QuotaBytes       int64
	Metrics          *metrics.Metrics
	Log              *slog.Logger
	Now              func() time.Time // 为空时用 time.Now
}

// Service 是业务入口。
type Service struct {
	store            *store.Store
	blobs            blob.Store
	hasher           *auth.Hasher
	signer           *auth.Signer
	box              *auth.SecretBox
	enumSecret       []byte
	registrationOpen bool
	quota            int64
	metrics          *metrics.Metrics
	log              *slog.Logger
	now              func() time.Time
	dummySalt        []byte
}

// New 创建业务层。
func New(o Options) *Service {
	now := o.Now
	if now == nil {
		now = time.Now
	}
	return &Service{
		store:            o.Store,
		blobs:            o.Blobs,
		hasher:           o.Hasher,
		signer:           o.Signer,
		box:              o.SecretBox,
		enumSecret:       o.EnumSecret,
		registrationOpen: o.RegistrationOpen,
		quota:            o.QuotaBytes,
		metrics:          o.Metrics,
		log:              o.Log,
		now:              func() time.Time { return now().UTC() },
		dummySalt:        auth.NewSalt(),
	}
}

// accessTTLSeconds 是会话对象里的 accessTokenExpiresIn。
var accessTTLSeconds = int(auth.AccessTTL / time.Second)

// 预置的业务错误。
var (
	errRegistrationClosed = apierr.New(http.StatusForbidden, apierr.CodeRegistrationClosed, "服务器已关闭注册")
	errEmailTaken         = apierr.New(http.StatusConflict, apierr.CodeEmailTaken, "该邮箱已注册")
	errVaultExists        = apierr.New(http.StatusConflict, apierr.CodeVaultExists, "该库 ID 已存在")
	errVersionConflict    = apierr.New(http.StatusConflict, apierr.CodeVersionConflict, "baseVersion 不是当前版本")
	errMissingChunks      = apierr.New(http.StatusBadRequest, apierr.CodeMissingChunks, "提交引用了未上传的块")
	errNotDeleted         = apierr.New(http.StatusConflict, apierr.CodeNotDeleted, "只能永久删除回收站里的文件")
	errQuotaExceeded      = apierr.New(http.StatusRequestEntityTooLarge, apierr.CodeQuotaExceeded, "超出存储配额")
	errRefreshReuse       = apierr.New(http.StatusUnauthorized, apierr.CodeRefreshReuse, "刷新令牌被重放,该设备已登出")
	errTOTPRequired       = apierr.New(http.StatusUnauthorized, apierr.CodeTOTPRequired, "账号已开启二次验证,请提供验证码")
	errTOTPInvalid        = apierr.New(http.StatusUnauthorized, apierr.CodeTOTPInvalid, "二次验证码错误")
)

// vaultErr 把库访问相关的仓储错误翻译成协议错误。
func vaultErr(err error) error {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return apierr.NotFound("库不存在")
	case errors.Is(err, store.ErrForbidden):
		return apierr.Forbidden()
	}
	return err
}

func (s *Service) audit(ctx context.Context, userID, deviceID, kind, ip string) error {
	return s.store.Audit(ctx, userID, deviceID, kind, ip)
}

func marshalKDF(k KDF) ([]byte, error) {
	b, err := json.Marshal(k)
	if err != nil {
		return nil, fmt.Errorf("序列化 KDF: %w", err)
	}
	return b, nil
}

func parseKDF(raw []byte) (KDF, error) {
	var k KDF
	if err := json.Unmarshal(raw, &k); err != nil {
		return KDF{}, fmt.Errorf("解析已存 KDF: %w", err)
	}
	return k, nil
}

// totpAAD 把 TOTP 密钥密文绑定到账号。
func totpAAD(userID string) []byte { return []byte("typoza/server/totp|" + userID) }

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("service: 读取系统随机数失败: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// deleteObjects 删除对象存储里的对象。记录已经删除,对象删除失败只会留下孤儿对象,
// 不影响用户可见结果,所以记错误日志与指标而不向调用方报错。
func (s *Service) deleteObjects(ctx context.Context, keys []string) {
	ctx = context.WithoutCancel(ctx)
	for _, key := range keys {
		if err := s.blobs.Delete(ctx, key); err != nil {
			s.metrics.BlobDeleteErrors.Inc()
			s.log.Error("删除对象失败,留下孤儿对象", "key", key, "err", err)
		}
	}
}
