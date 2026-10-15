// Package fakeserver 是内存假服务端,供 sdk 与宿主(如客户端辅助进程)的单元测试使用,
// 按 sync-protocol §4 实现最小子集:账号(prelogin/register/login/refresh/logout/recover/
// password/account)、设备、库、数据块、提交与变更、历史版本、回收站、WebSocket 事件。
//
// 它只验证客户端行为,不做服务端该做的安全加固(口令不做 Argon2、不限流、无 TOTP)。
package fakeserver

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/ComeHereToSee/typoza-backend/sdk/api"
	"github.com/ComeHereToSee/typoza-backend/sdk/internal/uuid"
)

const maxChunkBody = 4<<20 + 64

type user struct {
	id, email  string
	kdf        api.KDF
	authKey    []byte
	eak        []byte
	recAuthKey []byte
	reak       []byte
	createdAt  time.Time
	chunks     map[string][]byte
	devices    map[string]bool // deviceID → 是否有效
	deviceInfo map[string]api.DeviceInfo
}

type accessToken struct {
	userID, deviceID string
	expired          bool
}

type refreshToken struct {
	userID, deviceID string
	used             bool
}

type vault struct {
	id, owner string
	encName   []byte
	seq       int64
	createdAt time.Time
	files     map[string][]api.Version // fileID → 版本(旧→新)
}

type subscriber struct {
	userID string
	ch     chan api.Event
}

// Stats 是测试关心的计数。
type Stats struct {
	// ChunkPuts 是 PUT /v1/chunks 的请求次数(含已存在的幂等上传)。
	ChunkPuts int
	// Refreshes 是 POST /v1/auth/refresh 的请求次数。
	Refreshes int
	// Commits 是成功提交的次数。
	Commits int
}

// Server 是内存假服务端。
type Server struct {
	mu        sync.Mutex
	users     map[string]*user // email → user
	access    map[string]*accessToken
	refresh   map[string]*refreshToken
	recovery  map[string]string // recoveryToken → userID
	vaults    map[string]*vault
	subs      map[*subscriber]struct{}
	stats     Stats
	mux       *http.ServeMux
	closeOnce sync.Once
	done      chan struct{}
}

// New 构造假服务端。
func New() *Server {
	s := &Server{
		users:    make(map[string]*user),
		access:   make(map[string]*accessToken),
		refresh:  make(map[string]*refreshToken),
		recovery: make(map[string]string),
		vaults:   make(map[string]*vault),
		subs:     make(map[*subscriber]struct{}),
		mux:      http.NewServeMux(),
		done:     make(chan struct{}),
	}
	m := s.mux
	m.HandleFunc("POST /v1/auth/prelogin", s.prelogin)
	m.HandleFunc("POST /v1/auth/register", s.register)
	m.HandleFunc("POST /v1/auth/login", s.login)
	m.HandleFunc("POST /v1/auth/refresh", s.refreshTokens)
	m.HandleFunc("POST /v1/auth/logout", s.authed(s.logout))
	m.HandleFunc("POST /v1/auth/recover/begin", s.recoverBegin)
	m.HandleFunc("POST /v1/auth/recover/finish", s.recoverFinish)
	m.HandleFunc("GET /v1/account", s.authed(s.account))
	m.HandleFunc("POST /v1/account/password", s.authed(s.password))
	m.HandleFunc("GET /v1/devices", s.authed(s.listDevices))
	m.HandleFunc("DELETE /v1/devices/{deviceId}", s.authed(s.deleteDevice))
	m.HandleFunc("GET /v1/vaults", s.authed(s.listVaults))
	m.HandleFunc("POST /v1/vaults", s.authed(s.createVault))
	m.HandleFunc("POST /v1/chunks/check", s.authed(s.checkChunks))
	m.HandleFunc("PUT /v1/chunks/{chunkId}", s.authed(s.putChunk))
	m.HandleFunc("GET /v1/chunks/{chunkId}", s.authed(s.getChunk))
	m.HandleFunc("POST /v1/vaults/{vaultId}/files/{fileId}/commit", s.authed(s.commit))
	m.HandleFunc("GET /v1/vaults/{vaultId}/changes", s.authed(s.changes))
	m.HandleFunc("GET /v1/vaults/{vaultId}/files/{fileId}/versions", s.authed(s.versions))
	m.HandleFunc("GET /v1/vaults/{vaultId}/trash", s.authed(s.trash))
	m.HandleFunc("DELETE /v1/vaults/{vaultId}/files/{fileId}", s.authed(s.purge))
	m.HandleFunc("GET /v1/events", s.authed(s.events))
	return s
}

// Handler 返回 HTTP 处理器(交给 httptest.NewServer)。
func (s *Server) Handler() http.Handler { return s.mux }

// Close 结束所有 WebSocket 连接(在 httptest.Server.Close 之前调用,避免其等待长连接)。
func (s *Server) Close() { s.closeOnce.Do(func() { close(s.done) }) }

// Stats 返回计数快照。
func (s *Server) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

// ExpireAccessTokens 让当前所有访问令牌过期(下次使用返回 401 token_expired)。
func (s *Server) ExpireAccessTokens() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.access {
		t.expired = true
	}
}

// TamperChunk 翻转某账号下某块密文的最后一个字节,模拟存储被篡改。
func (s *Server) TamperChunk(chunkID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if c, ok := u.chunks[chunkID]; ok {
			c[len(c)-1] ^= 0xff
			return true
		}
	}
	return false
}

// ChunkIDs 返回所有账号下已存储的块 ID。
func (s *Server) ChunkIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var ids []string
	for _, u := range s.users {
		for id := range u.chunks {
			ids = append(ids, id)
		}
	}
	return ids
}

// ---- 工具 ----

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string, extra map[string]any) {
	e := map[string]any{"code": code, "message": msg}
	for k, v := range extra {
		e[k] = v
	}
	writeJSON(w, status, map[string]any{"error": e})
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, api.CodeInvalidRequest, err.Error(), nil)
		return false
	}
	return true
}

func randToken(prefix string) string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return prefix + base64.RawURLEncoding.EncodeToString(b)
}

func normEmail(e string) string { return strings.ToLower(strings.TrimSpace(e)) }

func defaultKDF(email string) api.KDF {
	sum := sha256.Sum256([]byte("fake-enum|" + email))
	return api.KDF{Algorithm: "argon2id", MemoryKiB: 65536, Iterations: 3, Parallelism: 4, Salt: sum[:16]}
}

func validKDF(k api.KDF) bool {
	return k.Algorithm == "argon2id" && k.MemoryKiB >= 19456 && k.Iterations >= 2 &&
		k.Parallelism >= 1 && k.Parallelism <= 16 && len(k.Salt) == 16
}

type ctxKey struct{}

type principal struct {
	userID, deviceID string
}

// authed 校验 Bearer 令牌:未知 → unauthorized,过期 → token_expired,设备已吊销 → unauthorized。
func (s *Server) authed(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		s.mu.Lock()
		at, ok := s.access[tok]
		var p principal
		status, code := 0, ""
		switch {
		case !ok:
			status, code = http.StatusUnauthorized, api.CodeUnauthorized
		case at.expired:
			status, code = http.StatusUnauthorized, api.CodeTokenExpired
		default:
			u := s.userByID(at.userID)
			if u == nil || !u.devices[at.deviceID] {
				status, code = http.StatusUnauthorized, api.CodeUnauthorized
			}
			p = principal{at.userID, at.deviceID}
		}
		s.mu.Unlock()
		if status != 0 {
			writeErr(w, status, code, "认证失败", nil)
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, p)))
	}
}

func who(r *http.Request) principal { return r.Context().Value(ctxKey{}).(principal) }

// userByID 需持有 s.mu。
func (s *Server) userByID(id string) *user {
	for _, u := range s.users {
		if u.id == id {
			return u
		}
	}
	return nil
}

// issueSession 新建或复用设备并签发令牌,需持有 s.mu。
func (s *Server) issueSession(u *user, deviceID string, dev api.Device) api.Session {
	if deviceID == "" || !u.devicesKnown(deviceID) {
		deviceID = uuid.New()
	}
	s.revokeDevice(u, deviceID)
	u.devices[deviceID] = true
	now := time.Now().UTC()
	info, ok := u.deviceInfo[deviceID]
	if !ok {
		info = api.DeviceInfo{ID: deviceID, CreatedAt: now}
	}
	info.Name, info.Platform, info.LastSeenAt = dev.Name, dev.Platform, now
	u.deviceInfo[deviceID] = info
	at, rt := randToken("at_"), randToken("tzr_")
	s.access[at] = &accessToken{userID: u.id, deviceID: deviceID}
	s.refresh[rt] = &refreshToken{userID: u.id, deviceID: deviceID}
	return api.Session{
		UserID: u.id, DeviceID: deviceID,
		AccessToken: at, AccessTokenExpiresIn: 900, RefreshToken: rt,
		EncryptedAccountKey: u.eak, KDF: u.kdf,
	}
}

func (u *user) devicesKnown(id string) bool {
	_, ok := u.devices[id]
	return ok
}

// revokeDevice 吊销设备的全部令牌,需持有 s.mu。
func (s *Server) revokeDevice(u *user, deviceID string) {
	if u == nil {
		return
	}
	for k, t := range s.access {
		if t.userID == u.id && t.deviceID == deviceID {
			delete(s.access, k)
		}
	}
	for k, t := range s.refresh {
		if t.userID == u.id && t.deviceID == deviceID {
			delete(s.refresh, k)
		}
	}
	if _, ok := u.devices[deviceID]; ok {
		u.devices[deviceID] = false
	}
}

// ---- 账号 ----

func (s *Server) prelogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email string `json:"email"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	email := normEmail(in.Email)
	s.mu.Lock()
	u := s.users[email]
	kdf := defaultKDF(email)
	if u != nil {
		kdf = u.kdf
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"kdf": kdf})
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	var in api.RegisterRequest
	if !readJSON(w, r, &in) {
		return
	}
	email := normEmail(in.Email)
	if email == "" || !validKDF(in.KDF) || len(in.AuthKey) != 32 || len(in.RecoveryAuthKey) != 32 ||
		len(in.EncryptedAccountKey) == 0 || len(in.RecoveryEncryptedAccountKey) == 0 {
		writeErr(w, http.StatusBadRequest, api.CodeInvalidRequest, "字段缺失或格式错", nil)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.users[email] != nil {
		writeErr(w, http.StatusConflict, api.CodeEmailTaken, "邮箱已注册", nil)
		return
	}
	u := &user{
		id: uuid.New(), email: email, kdf: in.KDF, authKey: in.AuthKey, eak: in.EncryptedAccountKey,
		recAuthKey: in.RecoveryAuthKey, reak: in.RecoveryEncryptedAccountKey, createdAt: time.Now().UTC(),
		chunks: make(map[string][]byte), devices: make(map[string]bool), deviceInfo: make(map[string]api.DeviceInfo),
	}
	s.users[email] = u
	writeJSON(w, http.StatusCreated, s.issueSession(u, "", in.Device))
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in api.LoginRequest
	if !readJSON(w, r, &in) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.users[normEmail(in.Email)]
	if u == nil || subtle.ConstantTimeCompare(u.authKey, in.AuthKey) != 1 {
		writeErr(w, http.StatusUnauthorized, api.CodeUnauthorized, "账号或密码错误", nil)
		return
	}
	writeJSON(w, http.StatusOK, s.issueSession(u, in.DeviceID, in.Device))
}

func (s *Server) refreshTokens(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RefreshToken string `json:"refreshToken"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.Refreshes++
	rt, ok := s.refresh[in.RefreshToken]
	if !ok {
		writeErr(w, http.StatusUnauthorized, api.CodeUnauthorized, "刷新令牌无效", nil)
		return
	}
	u := s.userByID(rt.userID)
	if rt.used {
		s.revokeDevice(u, rt.deviceID)
		writeErr(w, http.StatusUnauthorized, api.CodeRefreshReuse, "刷新令牌被重放", nil)
		return
	}
	rt.used = true
	at, nrt := randToken("at_"), randToken("tzr_")
	s.access[at] = &accessToken{userID: rt.userID, deviceID: rt.deviceID}
	s.refresh[nrt] = &refreshToken{userID: rt.userID, deviceID: rt.deviceID}
	writeJSON(w, http.StatusOK, api.TokenPair{AccessToken: at, AccessTokenExpiresIn: 900, RefreshToken: nrt})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	p := who(r)
	s.mu.Lock()
	s.revokeDevice(s.userByID(p.userID), p.deviceID)
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) recoverBegin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email           string  `json:"email"`
		RecoveryAuthKey api.B64 `json:"recoveryAuthKey"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.users[normEmail(in.Email)]
	if u == nil || subtle.ConstantTimeCompare(u.recAuthKey, in.RecoveryAuthKey) != 1 {
		writeErr(w, http.StatusUnauthorized, api.CodeUnauthorized, "恢复码错误", nil)
		return
	}
	tok := randToken("rt_")
	s.recovery[tok] = u.id
	writeJSON(w, http.StatusOK, api.RecoverBeginResponse{RecoveryEncryptedAccountKey: u.reak, RecoveryToken: tok})
}

func (s *Server) recoverFinish(w http.ResponseWriter, r *http.Request) {
	var in api.RecoverFinishRequest
	if !readJSON(w, r, &in) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	uid, ok := s.recovery[in.RecoveryToken]
	if !ok {
		writeErr(w, http.StatusUnauthorized, api.CodeUnauthorized, "恢复令牌无效", nil)
		return
	}
	if !validKDF(in.KDF) || len(in.AuthKey) != 32 || len(in.EncryptedAccountKey) == 0 {
		writeErr(w, http.StatusBadRequest, api.CodeInvalidRequest, "字段缺失或格式错", nil)
		return
	}
	delete(s.recovery, in.RecoveryToken)
	u := s.userByID(uid)
	u.kdf, u.authKey, u.eak = in.KDF, in.AuthKey, in.EncryptedAccountKey
	for d := range u.devices {
		s.revokeDevice(u, d)
	}
	writeJSON(w, http.StatusOK, s.issueSession(u, "", in.Device))
}

func (s *Server) account(w http.ResponseWriter, r *http.Request) {
	p := who(r)
	s.mu.Lock()
	u := s.userByID(p.userID)
	var used int64
	for _, c := range u.chunks {
		used += int64(len(c))
	}
	out := api.Account{UserID: u.id, Email: u.email, CreatedAt: u.createdAt,
		Usage: api.Usage{UsedBytes: used, QuotaBytes: 10 << 30}}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) password(w http.ResponseWriter, r *http.Request) {
	var in api.ChangePasswordRequest
	if !readJSON(w, r, &in) {
		return
	}
	p := who(r)
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.userByID(p.userID)
	if subtle.ConstantTimeCompare(u.authKey, in.AuthKey) != 1 {
		writeErr(w, http.StatusUnauthorized, api.CodeUnauthorized, "密码错误", nil)
		return
	}
	if !validKDF(in.NewKDF) || len(in.NewAuthKey) != 32 || len(in.NewEncryptedAccountKey) == 0 {
		writeErr(w, http.StatusBadRequest, api.CodeInvalidRequest, "字段缺失或格式错", nil)
		return
	}
	u.kdf, u.authKey, u.eak = in.NewKDF, in.NewAuthKey, in.NewEncryptedAccountKey
	for d := range u.devices {
		if d != p.deviceID {
			s.revokeDevice(u, d)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- 设备 ----

func (s *Server) listDevices(w http.ResponseWriter, r *http.Request) {
	p := who(r)
	s.mu.Lock()
	u := s.userByID(p.userID)
	out := make([]api.DeviceInfo, 0, len(u.devices))
	for id, active := range u.devices {
		if !active {
			continue
		}
		info := u.deviceInfo[id]
		info.Current = id == p.deviceID
		out = append(out, info)
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	writeJSON(w, http.StatusOK, map[string]any{"devices": out})
}

func (s *Server) deleteDevice(w http.ResponseWriter, r *http.Request) {
	p := who(r)
	id := r.PathValue("deviceId")
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.userByID(p.userID)
	if !u.devices[id] {
		writeErr(w, http.StatusNotFound, api.CodeNotFound, "设备不存在", nil)
		return
	}
	s.revokeDevice(u, id)
	w.WriteHeader(http.StatusNoContent)
}

// ---- 库 ----

func vaultJSON(v *vault) api.Vault {
	return api.Vault{ID: v.id, EncryptedName: v.encName, Seq: v.seq, CreatedAt: v.createdAt}
}

func (s *Server) listVaults(w http.ResponseWriter, r *http.Request) {
	p := who(r)
	s.mu.Lock()
	out := []api.Vault{}
	for _, v := range s.vaults {
		if v.owner == p.userID {
			out = append(out, vaultJSON(v))
		}
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	writeJSON(w, http.StatusOK, map[string]any{"vaults": out})
}

func (s *Server) createVault(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID            string  `json:"id"`
		EncryptedName api.B64 `json:"encryptedName"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if !uuid.Valid(in.ID) {
		writeErr(w, http.StatusBadRequest, api.CodeInvalidRequest, "id 不是 UUID", nil)
		return
	}
	p := who(r)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vaults[in.ID] != nil {
		writeErr(w, http.StatusConflict, api.CodeVaultExists, "库已存在", nil)
		return
	}
	v := &vault{id: in.ID, owner: p.userID, encName: in.EncryptedName, createdAt: time.Now().UTC(),
		files: make(map[string][]api.Version)}
	s.vaults[in.ID] = v
	writeJSON(w, http.StatusCreated, vaultJSON(v))
}

// vaultFor 取调用者名下的库;不存在 404、他人的 403。需持有 s.mu。
func (s *Server) vaultFor(w http.ResponseWriter, r *http.Request) *vault {
	v := s.vaults[r.PathValue("vaultId")]
	if v == nil {
		writeErr(w, http.StatusNotFound, api.CodeNotFound, "库不存在", nil)
		return nil
	}
	if v.owner != who(r).userID {
		writeErr(w, http.StatusForbidden, api.CodeForbidden, "无权访问", nil)
		return nil
	}
	return v
}

// ---- 数据块 ----

func validChunkID(id string) bool {
	if len(id) != 64 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil && strings.ToLower(id) == id
}

func (s *Server) checkChunks(w http.ResponseWriter, r *http.Request) {
	var in struct {
		IDs []string `json:"ids"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if len(in.IDs) > 1000 {
		writeErr(w, http.StatusBadRequest, api.CodeInvalidRequest, "ids 超过 1000 个", nil)
		return
	}
	p := who(r)
	s.mu.Lock()
	u := s.userByID(p.userID)
	missing := []string{}
	for _, id := range in.IDs {
		if _, ok := u.chunks[id]; !ok {
			missing = append(missing, id)
		}
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"missing": missing})
}

func (s *Server) putChunk(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("chunkId")
	if !validChunkID(id) {
		writeErr(w, http.StatusBadRequest, api.CodeInvalidRequest, "chunkId 格式错", nil)
		return
	}
	buf, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxChunkBody))
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, api.CodePayloadTooLarge, err.Error(), nil)
		return
	}
	p := who(r)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.ChunkPuts++
	u := s.userByID(p.userID)
	if _, ok := u.chunks[id]; ok {
		w.WriteHeader(http.StatusOK)
		return
	}
	u.chunks[id] = buf
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) getChunk(w http.ResponseWriter, r *http.Request) {
	p := who(r)
	s.mu.Lock()
	data, ok := s.userByID(p.userID).chunks[r.PathValue("chunkId")]
	data = append([]byte(nil), data...)
	s.mu.Unlock()
	if !ok {
		writeErr(w, http.StatusNotFound, api.CodeNotFound, "块不存在", nil)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(data)
}

// ---- 提交与变更 ----

func (s *Server) commit(w http.ResponseWriter, r *http.Request) {
	var in api.CommitRequest
	if !readJSON(w, r, &in) {
		return
	}
	fileID := r.PathValue("fileId")
	if !uuid.Valid(fileID) || len(in.Manifest) == 0 || in.Size < 0 {
		writeErr(w, http.StatusBadRequest, api.CodeInvalidRequest, "字段缺失或格式错", nil)
		return
	}
	if in.Deleted && (len(in.Chunks) != 0 || in.Size != 0) {
		writeErr(w, http.StatusBadRequest, api.CodeInvalidRequest, "墓碑不能带块", nil)
		return
	}
	p := who(r)
	s.mu.Lock()
	v := s.vaultFor(w, r)
	if v == nil {
		s.mu.Unlock()
		return
	}
	vers := v.files[fileID]
	var head *api.Version
	if len(vers) > 0 {
		h := vers[len(vers)-1]
		head = &h
	}
	headVersion := int64(0)
	if head != nil {
		headVersion = head.Version
	}
	if in.BaseVersion != headVersion {
		s.mu.Unlock()
		writeErr(w, http.StatusConflict, api.CodeVersionConflict, "版本冲突", map[string]any{"head": head})
		return
	}
	u := s.userByID(p.userID)
	missing := []string{}
	for _, id := range in.Chunks {
		if _, ok := u.chunks[id]; !ok {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		s.mu.Unlock()
		writeErr(w, http.StatusBadRequest, api.CodeMissingChunks, "块未上传", map[string]any{"missing": missing})
		return
	}
	v.seq++
	ver := api.Version{
		FileID: fileID, Version: headVersion + 1, Seq: v.seq, Manifest: in.Manifest, Deleted: in.Deleted,
		Size: in.Size, DeviceID: p.deviceID, CreatedAt: time.Now().UTC(),
	}
	v.files[fileID] = append(vers, ver)
	s.stats.Commits++
	ev := api.Event{Type: api.EventVaultChanged, VaultID: v.id, Seq: v.seq}
	for sub := range s.subs {
		if sub.userID == p.userID {
			select {
			case sub.ch <- ev:
			default: // 通知只是提示,订阅者处理不过来就丢弃
			}
		}
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, api.CommitResult{Version: ver.Version, Seq: ver.Seq})
}

func (s *Server) changes(w http.ResponseWriter, r *http.Request) {
	since, err := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, api.CodeInvalidRequest, "since 格式错", nil)
		return
	}
	limit := 500
	if l := r.URL.Query().Get("limit"); l != "" {
		if limit, err = strconv.Atoi(l); err != nil || limit < 1 || limit > 1000 {
			writeErr(w, http.StatusBadRequest, api.CodeInvalidRequest, "limit 格式错", nil)
			return
		}
	}
	s.mu.Lock()
	v := s.vaultFor(w, r)
	if v == nil {
		s.mu.Unlock()
		return
	}
	var latest []api.Version
	for _, vers := range v.files {
		if h := vers[len(vers)-1]; h.Seq > since {
			latest = append(latest, h)
		}
	}
	s.mu.Unlock()
	sort.Slice(latest, func(i, j int) bool { return latest[i].Seq < latest[j].Seq })
	hasMore := len(latest) > limit
	if hasMore {
		latest = latest[:limit]
	}
	cursor := since
	if len(latest) > 0 {
		cursor = latest[len(latest)-1].Seq
	}
	if latest == nil {
		latest = []api.Version{}
	}
	writeJSON(w, http.StatusOK, api.Changes{Changes: latest, Cursor: cursor, HasMore: hasMore})
}

func (s *Server) versions(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	v := s.vaultFor(w, r)
	if v == nil {
		s.mu.Unlock()
		return
	}
	vers := v.files[r.PathValue("fileId")]
	out := make([]api.Version, 0, len(vers))
	for i := len(vers) - 1; i >= 0; i-- {
		out = append(out, vers[i])
	}
	s.mu.Unlock()
	if len(out) == 0 {
		writeErr(w, http.StatusNotFound, api.CodeNotFound, "文件不存在", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"versions": out})
}

func (s *Server) trash(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	v := s.vaultFor(w, r)
	if v == nil {
		s.mu.Unlock()
		return
	}
	out := []api.TrashEntry{}
	for id, vers := range v.files {
		if h := vers[len(vers)-1]; h.Deleted {
			out = append(out, api.TrashEntry{FileID: id, Version: h.Version, Manifest: h.Manifest, DeletedAt: h.CreatedAt})
		}
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].FileID < out[j].FileID })
	writeJSON(w, http.StatusOK, map[string]any{"files": out})
}

func (s *Server) purge(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.vaultFor(w, r)
	if v == nil {
		return
	}
	id := r.PathValue("fileId")
	vers := v.files[id]
	if len(vers) == 0 {
		writeErr(w, http.StatusNotFound, api.CodeNotFound, "文件不存在", nil)
		return
	}
	if !vers[len(vers)-1].Deleted {
		writeErr(w, http.StatusConflict, api.CodeNotDeleted, "文件未删除", nil)
		return
	}
	delete(v.files, id)
	w.WriteHeader(http.StatusNoContent)
}

// ---- 实时通知 ----

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	p := who(r)
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer c.CloseNow()
	sub := &subscriber{userID: p.userID, ch: make(chan api.Event, 16)}
	s.mu.Lock()
	s.subs[sub] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.subs, sub)
		s.mu.Unlock()
	}()
	ctx := c.CloseRead(r.Context())
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			_ = c.Close(websocket.StatusGoingAway, "server closing")
			return
		case ev := <-sub.ch:
			if err := wsjson.Write(ctx, c, ev); err != nil {
				return
			}
		}
	}
}
