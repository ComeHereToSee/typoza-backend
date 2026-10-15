package api

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

// ---- 账号(协议 §4.1) ----

// Prelogin 取账号的 KDF 参数。未注册邮箱也会返回参数(防探测),所以不能据此判断账号是否存在。
func (c *Client) Prelogin(ctx context.Context, email string) (KDF, error) {
	var out struct {
		KDF KDF `json:"kdf"`
	}
	err := c.doJSON(ctx, http.MethodPost, "/v1/auth/prelogin", nil, map[string]string{"email": email}, &out, false)
	return out.KDF, err
}

// Register 注册账号。成功后客户端持有新会话的令牌并回调 OnTokens。
func (c *Client) Register(ctx context.Context, req RegisterRequest) (*Session, error) {
	return c.sessionCall(ctx, "/v1/auth/register", req)
}

// Login 登录。账号开启二次验证且未带 TOTPCode 时返回 totp_required 错误。
func (c *Client) Login(ctx context.Context, req LoginRequest) (*Session, error) {
	return c.sessionCall(ctx, "/v1/auth/login", req)
}

// RecoverBegin 用恢复认证密钥开始恢复流程。
func (c *Client) RecoverBegin(ctx context.Context, email string, recoveryAuthKey []byte) (*RecoverBeginResponse, error) {
	var out RecoverBeginResponse
	in := struct {
		Email           string `json:"email"`
		RecoveryAuthKey B64    `json:"recoveryAuthKey"`
	}{email, recoveryAuthKey}
	if err := c.doJSON(ctx, http.MethodPost, "/v1/auth/recover/begin", nil, in, &out, false); err != nil {
		return nil, err
	}
	return &out, nil
}

// RecoverFinish 提交新主密码相关字段完成恢复。成功后服务器吊销所有设备令牌,客户端持有新会话。
func (c *Client) RecoverFinish(ctx context.Context, req RecoverFinishRequest) (*Session, error) {
	return c.sessionCall(ctx, "/v1/auth/recover/finish", req)
}

func (c *Client) sessionCall(ctx context.Context, path string, in any) (*Session, error) {
	var s Session
	if err := c.doJSON(ctx, http.MethodPost, path, nil, in, &s, false); err != nil {
		return nil, err
	}
	if s.AccessToken == "" || s.RefreshToken == "" {
		return nil, fmt.Errorf("api: POST %s: 响应缺少令牌", path)
	}
	c.setTokens(s.Tokens())
	return &s, nil
}

// Logout 吊销当前设备的令牌链,并清空客户端持有的令牌。
func (c *Client) Logout(ctx context.Context) error {
	if err := c.doJSON(ctx, http.MethodPost, "/v1/auth/logout", nil, nil, nil, true); err != nil {
		return err
	}
	c.SetTokens(TokenPair{})
	return nil
}

// Account 取账号信息。
func (c *Client) Account(ctx context.Context) (*Account, error) {
	var out Account
	if err := c.doJSON(ctx, http.MethodGet, "/v1/account", nil, nil, &out, true); err != nil {
		return nil, err
	}
	return &out, nil
}

// ChangePassword 修改主密码(只重新包装 accountKey)。服务器会吊销除当前设备外的所有设备令牌。
func (c *Client) ChangePassword(ctx context.Context, req ChangePasswordRequest) error {
	return c.doJSON(ctx, http.MethodPost, "/v1/account/password", nil, req, nil, true)
}

// DeleteAccount 删除账号与全部数据。
func (c *Client) DeleteAccount(ctx context.Context, authKey []byte) error {
	in := struct {
		AuthKey B64 `json:"authKey"`
	}{authKey}
	if err := c.doJSON(ctx, http.MethodDelete, "/v1/account", nil, in, nil, true); err != nil {
		return err
	}
	c.SetTokens(TokenPair{})
	return nil
}

// TOTPSetup 生成(或覆盖未启用的)二次验证密钥。
func (c *Client) TOTPSetup(ctx context.Context) (*TOTPSetup, error) {
	var out TOTPSetup
	if err := c.doJSON(ctx, http.MethodPost, "/v1/account/totp/setup", nil, nil, &out, true); err != nil {
		return nil, err
	}
	return &out, nil
}

// TOTPEnable 用一个有效验证码启用二次验证。
func (c *Client) TOTPEnable(ctx context.Context, code string) error {
	return c.doJSON(ctx, http.MethodPost, "/v1/account/totp/enable", nil, map[string]string{"code": code}, nil, true)
}

// TOTPDisable 用一个有效验证码关闭二次验证。
func (c *Client) TOTPDisable(ctx context.Context, code string) error {
	return c.doJSON(ctx, http.MethodPost, "/v1/account/totp/disable", nil, map[string]string{"code": code}, nil, true)
}

// Devices 列出未吊销的设备。
func (c *Client) Devices(ctx context.Context) ([]DeviceInfo, error) {
	var out struct {
		Devices []DeviceInfo `json:"devices"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/v1/devices", nil, nil, &out, true); err != nil {
		return nil, err
	}
	return out.Devices, nil
}

// RevokeDevice 吊销指定设备的令牌链。
func (c *Client) RevokeDevice(ctx context.Context, deviceID string) error {
	return c.doJSON(ctx, http.MethodDelete, "/v1/devices/"+url.PathEscape(deviceID), nil, nil, nil, true)
}

// ---- 库(协议 §4.2) ----

// Vaults 列出账号下的库。
func (c *Client) Vaults(ctx context.Context) ([]Vault, error) {
	var out struct {
		Vaults []Vault `json:"vaults"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/v1/vaults", nil, nil, &out, true); err != nil {
		return nil, err
	}
	return out.Vaults, nil
}

// CreateVault 创建库;id 由客户端生成(小写 UUID),同 id 重复创建返回 vault_exists。
func (c *Client) CreateVault(ctx context.Context, id string, encryptedName []byte) (*Vault, error) {
	in := struct {
		ID            string `json:"id"`
		EncryptedName B64    `json:"encryptedName"`
	}{id, encryptedName}
	var out Vault
	if err := c.doJSON(ctx, http.MethodPost, "/v1/vaults", nil, in, &out, true); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteVault 删除库及其全部清单。
func (c *Client) DeleteVault(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodDelete, "/v1/vaults/"+url.PathEscape(id), nil, nil, nil, true)
}

// ---- 数据块(协议 §4.3) ----

// checkBatch 是 chunks/check 单次请求的 ID 数量上限。
const checkBatch = 1000

// CheckChunks 返回 ids 中服务器尚未存储的块 ID。超过 1000 个时自动分批。
func (c *Client) CheckChunks(ctx context.Context, ids []string) ([]string, error) {
	var missing []string
	for start := 0; start < len(ids); start += checkBatch {
		batch := ids[start:min(start+checkBatch, len(ids))]
		var out struct {
			Missing []string `json:"missing"`
		}
		in := struct {
			IDs []string `json:"ids"`
		}{batch}
		if err := c.doJSON(ctx, http.MethodPost, "/v1/chunks/check", nil, in, &out, true); err != nil {
			return nil, err
		}
		missing = append(missing, out.Missing...)
	}
	return missing, nil
}

// PutChunk 上传块密文(幂等:已存在时服务器返回 200)。
func (c *Client) PutChunk(ctx context.Context, id string, sealed []byte) error {
	_, err := c.send(ctx, request{
		method: http.MethodPut, path: "/v1/chunks/" + url.PathEscape(id), body: sealed,
		contentType: "application/octet-stream", auth: true, maxResp: maxJSONBytes,
	})
	return err
}

// GetChunk 下载块密文。
func (c *Client) GetChunk(ctx context.Context, id string) ([]byte, error) {
	resp, err := c.send(ctx, request{
		method: http.MethodGet, path: "/v1/chunks/" + url.PathEscape(id), auth: true, maxResp: maxChunkBytes,
	})
	if err != nil {
		return nil, err
	}
	return resp.body, nil
}

// ---- 文件提交与变更(协议 §4.4) ----

func filePath(vaultID, fileID string) string {
	return "/v1/vaults/" + url.PathEscape(vaultID) + "/files/" + url.PathEscape(fileID)
}

// Commit 提交文件新版本。baseVersion 不是服务器当前版本时返回 version_conflict(Error.Head 为当前版本);
// 引用了未上传的块时返回 missing_chunks(Error.Missing 为缺失列表)。
func (c *Client) Commit(ctx context.Context, vaultID, fileID string, req CommitRequest) (*CommitResult, error) {
	if req.Chunks == nil {
		req.Chunks = []string{} // 协议要求是数组而不是 null
	}
	var out CommitResult
	if err := c.doJSON(ctx, http.MethodPost, filePath(vaultID, fileID)+"/commit", nil, req, &out, true); err != nil {
		return nil, err
	}
	return &out, nil
}

// Changes 拉取 since 之后的变更(每个文件只返回最新版本)。limit ≤ 0 时用服务器默认值。
func (c *Client) Changes(ctx context.Context, vaultID string, since int64, limit int) (*Changes, error) {
	q := url.Values{"since": {strconv.FormatInt(since, 10)}}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	var out Changes
	if err := c.doJSON(ctx, http.MethodGet, "/v1/vaults/"+url.PathEscape(vaultID)+"/changes", q, nil, &out, true); err != nil {
		return nil, err
	}
	return &out, nil
}

// Versions 列出文件的历史版本(新→旧)。
func (c *Client) Versions(ctx context.Context, vaultID, fileID string) ([]Version, error) {
	var out struct {
		Versions []Version `json:"versions"`
	}
	if err := c.doJSON(ctx, http.MethodGet, filePath(vaultID, fileID)+"/versions", nil, nil, &out, true); err != nil {
		return nil, err
	}
	return out.Versions, nil
}

// Trash 列出库回收站中的文件(墓碑)。
func (c *Client) Trash(ctx context.Context, vaultID string) ([]TrashEntry, error) {
	var out struct {
		Files []TrashEntry `json:"files"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/v1/vaults/"+url.PathEscape(vaultID)+"/trash", nil, nil, &out, true); err != nil {
		return nil, err
	}
	return out.Files, nil
}

// PurgeFile 永久删除回收站中的文件;文件未删除时返回 not_deleted。
func (c *Client) PurgeFile(ctx context.Context, vaultID, fileID string) error {
	return c.doJSON(ctx, http.MethodDelete, filePath(vaultID, fileID), nil, nil, nil, true)
}
