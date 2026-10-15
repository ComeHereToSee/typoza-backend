package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// B64 是放进 JSON 的二进制字段,按协议编码为 base64url 无填充(RFC 4648 §5)。
// 标准库 []byte 默认用带填充的标准 base64,服务器会拒绝,所以单独定义类型。
type B64 []byte

// MarshalJSON 编码为 base64url 无填充字符串。
func (b B64) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.RawURLEncoding.EncodeToString(b))
}

// UnmarshalJSON 严格按 base64url 无填充解码。
func (b *B64) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("api: base64url 字段不是字符串: %w", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return fmt.Errorf("api: base64url 字段解码失败: %w", err)
	}
	*b = raw
	return nil
}

// KDF 是 Argon2id 参数(prelogin、注册、会话对象中的 kdf 字段)。
type KDF struct {
	Algorithm   string `json:"algorithm"`
	MemoryKiB   uint32 `json:"memoryKiB"`
	Iterations  uint32 `json:"iterations"`
	Parallelism uint32 `json:"parallelism"`
	Salt        B64    `json:"salt"`
}

// Device 是登录/注册时上报的设备信息。
type Device struct {
	Name     string `json:"name"`
	Platform string `json:"platform"`
}

// TokenPair 是一对访问令牌与刷新令牌。调用方应把它持久化(macOS 上放钥匙串),
// 下次启动用 Client.SetTokens 恢复会话。
type TokenPair struct {
	AccessToken          string `json:"accessToken"`
	AccessTokenExpiresIn int64  `json:"accessTokenExpiresIn"`
	RefreshToken         string `json:"refreshToken"`
}

// Session 是注册、登录、恢复成功后返回的会话对象。
type Session struct {
	UserID               string `json:"userId"`
	DeviceID             string `json:"deviceId"`
	AccessToken          string `json:"accessToken"`
	AccessTokenExpiresIn int64  `json:"accessTokenExpiresIn"`
	RefreshToken         string `json:"refreshToken"`
	EncryptedAccountKey  B64    `json:"encryptedAccountKey"`
	KDF                  KDF    `json:"kdf"`
}

// Tokens 取出会话中的令牌对。
func (s *Session) Tokens() TokenPair {
	return TokenPair{AccessToken: s.AccessToken, AccessTokenExpiresIn: s.AccessTokenExpiresIn, RefreshToken: s.RefreshToken}
}

// RegisterRequest 是 POST /v1/auth/register 的请求体。
type RegisterRequest struct {
	Email                       string `json:"email"`
	KDF                         KDF    `json:"kdf"`
	AuthKey                     B64    `json:"authKey"`
	EncryptedAccountKey         B64    `json:"encryptedAccountKey"`
	RecoveryAuthKey             B64    `json:"recoveryAuthKey"`
	RecoveryEncryptedAccountKey B64    `json:"recoveryEncryptedAccountKey"`
	Device                      Device `json:"device"`
}

// LoginRequest 是 POST /v1/auth/login 的请求体。
type LoginRequest struct {
	Email    string `json:"email"`
	AuthKey  B64    `json:"authKey"`
	TOTPCode string `json:"totpCode,omitempty"`
	Device   Device `json:"device"`
	// DeviceID 非空且属于该账号时服务器复用设备记录(吊销其旧令牌链)。
	DeviceID string `json:"deviceId,omitempty"`
}

// RecoverBeginResponse 是 POST /v1/auth/recover/begin 的响应。
type RecoverBeginResponse struct {
	RecoveryEncryptedAccountKey B64    `json:"recoveryEncryptedAccountKey"`
	RecoveryToken               string `json:"recoveryToken"`
}

// RecoverFinishRequest 是 POST /v1/auth/recover/finish 的请求体。
type RecoverFinishRequest struct {
	RecoveryToken       string `json:"recoveryToken"`
	KDF                 KDF    `json:"kdf"`
	AuthKey             B64    `json:"authKey"`
	EncryptedAccountKey B64    `json:"encryptedAccountKey"`
	Device              Device `json:"device"`
}

// Usage 是存储用量。
type Usage struct {
	UsedBytes  int64 `json:"usedBytes"`
	QuotaBytes int64 `json:"quotaBytes"`
}

// Account 是 GET /v1/account 的响应。
type Account struct {
	UserID      string    `json:"userId"`
	Email       string    `json:"email"`
	TOTPEnabled bool      `json:"totpEnabled"`
	CreatedAt   time.Time `json:"createdAt"`
	Usage       Usage     `json:"usage"`
}

// ChangePasswordRequest 是 POST /v1/account/password 的请求体。
type ChangePasswordRequest struct {
	AuthKey                B64 `json:"authKey"`
	NewKDF                 KDF `json:"newKdf"`
	NewAuthKey             B64 `json:"newAuthKey"`
	NewEncryptedAccountKey B64 `json:"newEncryptedAccountKey"`
}

// TOTPSetup 是 POST /v1/account/totp/setup 的响应。
type TOTPSetup struct {
	Secret     string `json:"secret"`
	OTPAuthURL string `json:"otpauthUrl"`
}

// DeviceInfo 是设备列表中的一项。
type DeviceInfo struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Platform   string    `json:"platform"`
	CreatedAt  time.Time `json:"createdAt"`
	LastSeenAt time.Time `json:"lastSeenAt"`
	Current    bool      `json:"current"`
}

// Vault 是库对象。
type Vault struct {
	ID            string    `json:"id"`
	EncryptedName B64       `json:"encryptedName"`
	Seq           int64     `json:"seq"`
	CreatedAt     time.Time `json:"createdAt"`
}

// Version 是文件版本对象(changes、versions、409 head 中使用)。
type Version struct {
	FileID    string    `json:"fileId"`
	Version   int64     `json:"version"`
	Seq       int64     `json:"seq"`
	Manifest  B64       `json:"manifest"`
	Deleted   bool      `json:"deleted"`
	Size      int64     `json:"size"`
	DeviceID  string    `json:"deviceId"`
	CreatedAt time.Time `json:"createdAt"`
}

// CommitRequest 是 POST /v1/vaults/{vaultId}/files/{fileId}/commit 的请求体。
type CommitRequest struct {
	BaseVersion int64    `json:"baseVersion"`
	Manifest    B64      `json:"manifest"`
	Chunks      []string `json:"chunks"`
	Size        int64    `json:"size"`
	Deleted     bool     `json:"deleted"`
}

// CommitResult 是提交成功的响应。
type CommitResult struct {
	Version int64 `json:"version"`
	Seq     int64 `json:"seq"`
}

// Changes 是 GET /v1/vaults/{vaultId}/changes 的响应。
type Changes struct {
	Changes []Version `json:"changes"`
	Cursor  int64     `json:"cursor"`
	HasMore bool      `json:"hasMore"`
}

// TrashEntry 是回收站中的一项(墓碑清单含原路径)。
type TrashEntry struct {
	FileID    string    `json:"fileId"`
	Version   int64     `json:"version"`
	Manifest  B64       `json:"manifest"`
	DeletedAt time.Time `json:"deletedAt"`
}

// Event 是 WebSocket 推送的事件。
type Event struct {
	Type    string `json:"type"`
	VaultID string `json:"vaultId"`
	Seq     int64  `json:"seq"`
}

// EventVaultChanged 是「库有新提交」事件的 type 值。
const EventVaultChanged = "vault.changed"
