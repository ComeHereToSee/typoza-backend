package service

import (
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/ComeHereToSee/typoza-backend/internal/store"
)

// 本文件定义对外 JSON 形状(字段名与协议 §4 逐字一致)。时间统一 UTC、RFC 3339 毫秒精度。

const timeLayout = "2006-01-02T15:04:05.000Z"

func formatTime(t time.Time) string { return t.UTC().Format(timeLayout) }

// b64 是协议规定的 base64url 无填充编码。
func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// 客户端主密码 KDF 的协议下限(协议 §4.1 register)与默认值(协议 §2)。
const (
	kdfAlgorithm      = "argon2id"
	kdfMinMemoryKiB   = 19456
	kdfMinIterations  = 2
	kdfMinParallelism = 1
	kdfMaxParallelism = 16
	kdfSaltLen        = 16

	defaultKDFMemoryKiB   = 65536
	defaultKDFIterations  = 3
	defaultKDFParallelism = 4
)

// KDF 是客户端主密码派生参数。服务器不使用它,只负责保存与在 prelogin / 会话里回传。
type KDF struct {
	Algorithm   string `json:"algorithm"`
	MemoryKiB   int64  `json:"memoryKiB"`
	Iterations  int64  `json:"iterations"`
	Parallelism int64  `json:"parallelism"`
	Salt        string `json:"salt"`
}

// Validate 检查算法与协议下限;salt 必须是 16 字节的 base64url 无填充。
func (k KDF) Validate() error {
	switch {
	case k.Algorithm != kdfAlgorithm:
		return fmt.Errorf("kdf.algorithm 只支持 %s", kdfAlgorithm)
	case k.MemoryKiB < kdfMinMemoryKiB:
		return fmt.Errorf("kdf.memoryKiB 不得低于 %d", kdfMinMemoryKiB)
	case k.Iterations < kdfMinIterations:
		return fmt.Errorf("kdf.iterations 不得低于 %d", kdfMinIterations)
	case k.Parallelism < kdfMinParallelism || k.Parallelism > kdfMaxParallelism:
		return fmt.Errorf("kdf.parallelism 应在 %d~%d 之间", kdfMinParallelism, kdfMaxParallelism)
	}
	salt, err := base64.RawURLEncoding.DecodeString(k.Salt)
	if err != nil || len(salt) != kdfSaltLen {
		return errors.New("kdf.salt 应为 16 字节的 base64url(无填充)")
	}
	return nil
}

func defaultKDF(salt []byte) KDF {
	return KDF{
		Algorithm:   kdfAlgorithm,
		MemoryKiB:   defaultKDFMemoryKiB,
		Iterations:  defaultKDFIterations,
		Parallelism: defaultKDFParallelism,
		Salt:        b64(salt),
	}
}

// DeviceInfo 是登录时上报的设备信息。
type DeviceInfo struct {
	Name     string `json:"name"`
	Platform string `json:"platform"`
}

// Principal 是已认证的调用方。IP 只用于审计。
type Principal struct {
	UserID   string
	DeviceID string
	IP       string
}

// Session 是会话对象(协议 §4.1)。
type Session struct {
	UserID               string `json:"userId"`
	DeviceID             string `json:"deviceId"`
	AccessToken          string `json:"accessToken"`
	AccessTokenExpiresIn int    `json:"accessTokenExpiresIn"`
	RefreshToken         string `json:"refreshToken"`
	EncryptedAccountKey  string `json:"encryptedAccountKey"`
	KDF                  KDF    `json:"kdf"`
}

// Tokens 是刷新接口的响应。
type Tokens struct {
	AccessToken          string `json:"accessToken"`
	AccessTokenExpiresIn int    `json:"accessTokenExpiresIn"`
	RefreshToken         string `json:"refreshToken"`
}

// RecoveryStart 是 recover/begin 的响应。
type RecoveryStart struct {
	RecoveryEncryptedAccountKey string `json:"recoveryEncryptedAccountKey"`
	RecoveryToken               string `json:"recoveryToken"`
}

// Account 是 GET /v1/account 的响应。
type Account struct {
	UserID      string `json:"userId"`
	Email       string `json:"email"`
	TOTPEnabled bool   `json:"totpEnabled"`
	CreatedAt   string `json:"createdAt"`
	Usage       Usage  `json:"usage"`
}

// Usage 是存储用量。
type Usage struct {
	UsedBytes  int64 `json:"usedBytes"`
	QuotaBytes int64 `json:"quotaBytes"`
}

// TOTPSetup 是 totp/setup 的响应。
type TOTPSetup struct {
	Secret     string `json:"secret"`
	OtpauthURL string `json:"otpauthUrl"`
}

// Device 是设备列表项。
type Device struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Platform   string `json:"platform"`
	CreatedAt  string `json:"createdAt"`
	LastSeenAt string `json:"lastSeenAt"`
	Current    bool   `json:"current"`
}

// Vault 是库对象。
type Vault struct {
	ID            string `json:"id"`
	EncryptedName string `json:"encryptedName"`
	Seq           int64  `json:"seq"`
	CreatedAt     string `json:"createdAt"`
}

func vaultDTO(v store.Vault) Vault {
	return Vault{ID: v.ID, EncryptedName: v.EncryptedName, Seq: v.Seq, CreatedAt: formatTime(v.CreatedAt)}
}

// Version 是版本对象(协议 §4.4)。
type Version struct {
	FileID    string `json:"fileId"`
	Version   int64  `json:"version"`
	Seq       int64  `json:"seq"`
	Manifest  string `json:"manifest"`
	Deleted   bool   `json:"deleted"`
	Size      int64  `json:"size"`
	DeviceID  string `json:"deviceId"`
	CreatedAt string `json:"createdAt"`
}

func versionDTO(v store.Version) Version {
	return Version{
		FileID:    v.FileID,
		Version:   v.Version,
		Seq:       v.Seq,
		Manifest:  b64(v.Manifest),
		Deleted:   v.Deleted,
		Size:      v.Size,
		DeviceID:  v.DeviceID,
		CreatedAt: formatTime(v.CreatedAt),
	}
}

func versionDTOs(vs []store.Version) []Version {
	out := make([]Version, 0, len(vs))
	for _, v := range vs {
		out = append(out, versionDTO(v))
	}
	return out
}

// CommitResult 是提交成功的响应。
type CommitResult struct {
	Version int64 `json:"version"`
	Seq     int64 `json:"seq"`
}

// ChangesPage 是 changes 接口的响应。
type ChangesPage struct {
	Changes []Version `json:"changes"`
	Cursor  int64     `json:"cursor"`
	HasMore bool      `json:"hasMore"`
}

// TrashItem 是回收站条目。
type TrashItem struct {
	FileID    string `json:"fileId"`
	Version   int64  `json:"version"`
	Manifest  string `json:"manifest"`
	DeletedAt string `json:"deletedAt"`
}
