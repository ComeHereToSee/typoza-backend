package app_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/ComeHereToSee/typoza-backend/internal/blob"
	"github.com/ComeHereToSee/typoza-backend/internal/config"
	"github.com/ComeHereToSee/typoza-backend/internal/service"
)

func TestVaultsAndAccessControl(t *testing.T) {
	e := newEnv(t, nil)
	a := e.register(uniqueEmail(t)).session
	b := e.register(uniqueEmail(t)).session

	vaultID := newUUID(t)
	name := b64(randBytes(t, 40))
	var v service.Vault
	e.call(http.MethodPost, "/v1/vaults", a.AccessToken, map[string]string{"id": vaultID, "encryptedName": name}, http.StatusCreated, &v)
	if v.ID != vaultID || v.EncryptedName != name || v.Seq != 0 || v.CreatedAt == "" {
		t.Fatalf("库对象不符: %+v", v)
	}
	e.expectError(http.MethodPost, "/v1/vaults", a.AccessToken, map[string]string{"id": vaultID, "encryptedName": name}, http.StatusConflict, "vault_exists")
	e.expectError(http.MethodPost, "/v1/vaults", b.AccessToken, map[string]string{"id": vaultID, "encryptedName": name}, http.StatusConflict, "vault_exists")
	e.expectError(http.MethodPost, "/v1/vaults", a.AccessToken, map[string]string{"id": strings.ToUpper(newUUID(t)), "encryptedName": name}, http.StatusBadRequest, "invalid_request")

	var list struct {
		Vaults []service.Vault `json:"vaults"`
	}
	e.call(http.MethodGet, "/v1/vaults", a.AccessToken, nil, http.StatusOK, &list)
	if len(list.Vaults) != 1 || list.Vaults[0].ID != vaultID {
		t.Fatalf("A 应只看到自己的库: %+v", list.Vaults)
	}
	e.call(http.MethodGet, "/v1/vaults", b.AccessToken, nil, http.StatusOK, &list)
	if len(list.Vaults) != 0 {
		t.Fatalf("B 不应看到 A 的库")
	}

	fileID := newUUID(t)
	commitPath := "/v1/vaults/" + vaultID + "/files/" + fileID + "/commit"
	e.expectError(http.MethodPost, commitPath, b.AccessToken, commitBody(0, nil, 0, false, randBytes(t, 10)), http.StatusForbidden, "forbidden")
	e.expectError(http.MethodGet, "/v1/vaults/"+vaultID+"/changes", b.AccessToken, nil, http.StatusForbidden, "forbidden")
	e.expectError(http.MethodGet, "/v1/vaults/"+vaultID+"/trash", b.AccessToken, nil, http.StatusForbidden, "forbidden")
	e.expectError(http.MethodDelete, "/v1/vaults/"+vaultID, b.AccessToken, nil, http.StatusForbidden, "forbidden")
	missing := newUUID(t)
	e.expectError(http.MethodGet, "/v1/vaults/"+missing+"/changes", a.AccessToken, nil, http.StatusNotFound, "not_found")
	e.expectError(http.MethodDelete, "/v1/vaults/"+missing, a.AccessToken, nil, http.StatusNotFound, "not_found")

	e.commit(a.AccessToken, vaultID, fileID, 0, nil, 0, false)
	e.call(http.MethodDelete, "/v1/vaults/"+vaultID, a.AccessToken, nil, http.StatusNoContent, nil)
	e.expectError(http.MethodGet, "/v1/vaults/"+vaultID+"/changes", a.AccessToken, nil, http.StatusNotFound, "not_found")
	if n := e.queryInt(`SELECT count(*) FROM file_versions`); n != 0 {
		t.Fatalf("删库应级联删除全部版本,剩 %d", n)
	}
}

func TestChunksUploadCheckDownloadIsolation(t *testing.T) {
	e := newEnv(t, nil)
	a := e.register(uniqueEmail(t)).session
	b := e.register(uniqueEmail(t)).session

	id1, id2 := newChunkID(t), newChunkID(t)
	data := randBytes(t, 4096)
	var check struct {
		Missing []string `json:"missing"`
	}
	e.call(http.MethodPost, "/v1/chunks/check", a.AccessToken, map[string]any{"ids": []string{id1, id2, id1}}, http.StatusOK, &check)
	if len(check.Missing) != 2 || check.Missing[0] != id1 || check.Missing[1] != id2 {
		t.Fatalf("missing 应去重并保持顺序: %v", check.Missing)
	}

	e.putChunk(a.AccessToken, id1, data, http.StatusCreated)
	e.putChunk(a.AccessToken, id1, data, http.StatusOK) // 幂等
	e.call(http.MethodPost, "/v1/chunks/check", a.AccessToken, map[string]any{"ids": []string{id1, id2}}, http.StatusOK, &check)
	if len(check.Missing) != 1 || check.Missing[0] != id2 {
		t.Fatalf("上传后只缺 id2: %v", check.Missing)
	}

	r := e.call(http.MethodGet, "/v1/chunks/"+id1, a.AccessToken, nil, http.StatusOK, nil)
	if !bytes.Equal(r.body, data) || r.header.Get("Content-Type") != "application/octet-stream" || r.header.Get("Content-Length") != strconv.Itoa(len(data)) {
		t.Fatalf("下载内容或响应头不符")
	}

	// 块按账号隔离。
	e.expectError(http.MethodGet, "/v1/chunks/"+id1, b.AccessToken, nil, http.StatusNotFound, "not_found")
	e.call(http.MethodPost, "/v1/chunks/check", b.AccessToken, map[string]any{"ids": []string{id1}}, http.StatusOK, &check)
	if len(check.Missing) != 1 {
		t.Fatalf("B 不应看到 A 的块")
	}
	e.putChunk(b.AccessToken, id1, data, http.StatusCreated)

	// 参数校验。
	e.expectError(http.MethodGet, "/v1/chunks/"+strings.ToUpper(id1), a.AccessToken, nil, http.StatusBadRequest, "invalid_request")
	e.expectError(http.MethodPut, "/v1/chunks/"+newChunkID(t), a.AccessToken, []byte{}, http.StatusBadRequest, "invalid_request")
	tooMany := make([]string, 1001)
	for i := range tooMany {
		tooMany[i] = id1
	}
	e.expectError(http.MethodPost, "/v1/chunks/check", a.AccessToken, map[string]any{"ids": tooMany}, http.StatusBadRequest, "invalid_request")
	e.putChunk(a.AccessToken, newChunkID(t), make([]byte, 4<<20+64), http.StatusCreated)
}

func TestCommitConflictAndMissingChunks(t *testing.T) {
	e := newEnv(t, nil)
	s := e.register(uniqueEmail(t)).session
	vaultID := e.createVault(s.AccessToken)
	fileID := newUUID(t)
	path := "/v1/vaults/" + vaultID + "/files/" + fileID + "/commit"

	c1, c2 := newChunkID(t), newChunkID(t)
	e.putChunk(s.AccessToken, c1, randBytes(t, 100), http.StatusCreated)

	ae := e.expectError(http.MethodPost, path, s.AccessToken, commitBody(0, []string{c1, c2, c2}, 300, false, randBytes(t, 32)), http.StatusBadRequest, "missing_chunks")
	if len(ae.Error.Missing) != 1 || ae.Error.Missing[0] != c2 {
		t.Fatalf("missing 应只含 c2: %v", ae.Error.Missing)
	}
	e.putChunk(s.AccessToken, c2, randBytes(t, 100), http.StatusCreated)

	r1 := e.commit(s.AccessToken, vaultID, fileID, 0, []string{c1, c2, c2}, 300, false)
	if r1.Version != 1 || r1.Seq != 1 {
		t.Fatalf("首个版本应为 version=1 seq=1: %+v", r1)
	}
	r2 := e.commit(s.AccessToken, vaultID, fileID, 1, []string{c1}, 100, false)
	if r2.Version != 2 || r2.Seq != 2 {
		t.Fatalf("第二个版本应为 version=2 seq=2: %+v", r2)
	}

	// 基于旧版本提交 → 409,附当前 head。
	ae = e.expectError(http.MethodPost, path, s.AccessToken, commitBody(1, nil, 0, false, randBytes(t, 32)), http.StatusConflict, "version_conflict")
	var head version
	if err := json.Unmarshal(ae.Error.Head, &head); err != nil {
		t.Fatalf("冲突响应应附 head 版本对象: %s", ae.Error.Head)
	}
	if head.FileID != fileID || head.Version != 2 || head.Seq != 2 || head.Size != 100 || head.DeviceID != s.DeviceID || head.Manifest == "" || head.CreatedAt == "" {
		t.Fatalf("head 版本对象不符: %+v", head)
	}
	// 新文件却带非零 baseVersion → 409,head 为 null。
	other := newUUID(t)
	ae = e.expectError(http.MethodPost, "/v1/vaults/"+vaultID+"/files/"+other+"/commit", s.AccessToken, commitBody(3, nil, 0, false, randBytes(t, 32)), http.StatusConflict, "version_conflict")
	if string(ae.Error.Head) != "null" {
		t.Fatalf("文件不存在时 head 应为 null: %s", ae.Error.Head)
	}

	// 墓碑必须不引用块。
	e.expectError(http.MethodPost, path, s.AccessToken, commitBody(2, []string{c1}, 100, true, randBytes(t, 32)), http.StatusBadRequest, "invalid_request")
	// 缺字段、负数、非法 base64。
	e.expectError(http.MethodPost, path, s.AccessToken, map[string]any{"manifest": b64(randBytes(t, 8)), "chunks": []string{}, "size": 0}, http.StatusBadRequest, "invalid_request")
	e.expectError(http.MethodPost, path, s.AccessToken, commitBody(-1, nil, 0, false, randBytes(t, 8)), http.StatusBadRequest, "invalid_request")
	e.expectError(http.MethodPost, path, s.AccessToken, map[string]any{"baseVersion": 2, "manifest": "a+b/", "chunks": []string{}, "size": 0}, http.StatusBadRequest, "invalid_request")
}

func TestChangesPaginationLatestOnly(t *testing.T) {
	e := newEnv(t, nil)
	s := e.register(uniqueEmail(t)).session
	vaultID := e.createVault(s.AccessToken)
	f1, f2, f3 := newUUID(t), newUUID(t), newUUID(t)
	e.commit(s.AccessToken, vaultID, f1, 0, nil, 0, false) // seq 1
	e.commit(s.AccessToken, vaultID, f2, 0, nil, 0, false) // seq 2
	e.commit(s.AccessToken, vaultID, f3, 0, nil, 0, false) // seq 3
	e.commit(s.AccessToken, vaultID, f1, 1, nil, 0, false) // seq 4:f1 最新版本移到末尾
	e.commit(s.AccessToken, vaultID, f2, 1, nil, 0, true)  // seq 5:f2 删除墓碑

	get := func(since int64, limit int) changesPage {
		var p changesPage
		path := "/v1/vaults/" + vaultID + "/changes?since=" + strconv.FormatInt(since, 10)
		if limit > 0 {
			path += "&limit=" + strconv.Itoa(limit)
		}
		e.call(http.MethodGet, path, s.AccessToken, nil, http.StatusOK, &p)
		return p
	}

	all := get(0, 0)
	if len(all.Changes) != 3 || all.HasMore || all.Cursor != 5 {
		t.Fatalf("每个文件只返回最新版本: %+v", all)
	}
	wantOrder := []struct {
		file    string
		version int64
		seq     int64
		deleted bool
	}{{f3, 1, 3, false}, {f1, 2, 4, false}, {f2, 2, 5, true}}
	for i, w := range wantOrder {
		c := all.Changes[i]
		if c.FileID != w.file || c.Version != w.version || c.Seq != w.seq || c.Deleted != w.deleted {
			t.Fatalf("第 %d 条变更不符: %+v,期望 %+v", i, c, w)
		}
	}

	p1 := get(0, 2)
	if len(p1.Changes) != 2 || !p1.HasMore || p1.Cursor != 4 {
		t.Fatalf("第一页: %+v", p1)
	}
	p2 := get(p1.Cursor, 2)
	if len(p2.Changes) != 1 || p2.HasMore || p2.Cursor != 5 || p2.Changes[0].FileID != f2 {
		t.Fatalf("第二页: %+v", p2)
	}
	p3 := get(p2.Cursor, 2)
	if len(p3.Changes) != 0 || p3.HasMore || p3.Cursor != 5 {
		t.Fatalf("无变化时 cursor 应等于 since: %+v", p3)
	}
	if p := get(0, 5000); len(p.Changes) != 3 {
		t.Fatalf("limit 超过上限应按 1000 处理")
	}
	e.expectError(http.MethodGet, "/v1/vaults/"+vaultID+"/changes?since=-1", s.AccessToken, nil, http.StatusBadRequest, "invalid_request")
	e.expectError(http.MethodGet, "/v1/vaults/"+vaultID+"/changes?limit=abc", s.AccessToken, nil, http.StatusBadRequest, "invalid_request")

	var vaults struct {
		Vaults []service.Vault `json:"vaults"`
	}
	e.call(http.MethodGet, "/v1/vaults", s.AccessToken, nil, http.StatusOK, &vaults)
	if vaults.Vaults[0].Seq != 5 {
		t.Fatalf("库 seq 应为 5,实际 %d", vaults.Vaults[0].Seq)
	}
}

func TestVersionsTrashAndPurge(t *testing.T) {
	e := newEnv(t, nil)
	s := e.register(uniqueEmail(t)).session
	vaultID := e.createVault(s.AccessToken)
	fileID := newUUID(t)
	base := "/v1/vaults/" + vaultID + "/files/" + fileID

	e.expectError(http.MethodGet, base+"/versions", s.AccessToken, nil, http.StatusNotFound, "not_found")
	e.commit(s.AccessToken, vaultID, fileID, 0, nil, 0, false)
	e.commit(s.AccessToken, vaultID, fileID, 1, nil, 0, false)

	var vs struct {
		Versions []version `json:"versions"`
	}
	e.call(http.MethodGet, base+"/versions", s.AccessToken, nil, http.StatusOK, &vs)
	if len(vs.Versions) != 2 || vs.Versions[0].Version != 2 || vs.Versions[1].Version != 1 {
		t.Fatalf("历史版本应新 → 旧: %+v", vs.Versions)
	}

	e.expectError(http.MethodDelete, base, s.AccessToken, nil, http.StatusConflict, "not_deleted")

	tombstone := randBytes(t, 32)
	e.call(http.MethodPost, base+"/commit", s.AccessToken, commitBody(2, nil, 0, true, tombstone), http.StatusOK, nil)
	var trash struct {
		Files []service.TrashItem `json:"files"`
	}
	e.call(http.MethodGet, "/v1/vaults/"+vaultID+"/trash", s.AccessToken, nil, http.StatusOK, &trash)
	if len(trash.Files) != 1 || trash.Files[0].FileID != fileID || trash.Files[0].Version != 3 || trash.Files[0].Manifest != b64(tombstone) || trash.Files[0].DeletedAt == "" {
		t.Fatalf("回收站条目不符: %+v", trash.Files)
	}

	// 从回收站恢复 = 基于墓碑版本再提交一个非删除版本。
	e.commit(s.AccessToken, vaultID, fileID, 3, nil, 0, false)
	e.call(http.MethodGet, "/v1/vaults/"+vaultID+"/trash", s.AccessToken, nil, http.StatusOK, &trash)
	if len(trash.Files) != 0 {
		t.Fatalf("恢复后回收站应为空")
	}
	e.commit(s.AccessToken, vaultID, fileID, 4, nil, 0, true)

	e.call(http.MethodDelete, base, s.AccessToken, nil, http.StatusNoContent, nil)
	e.expectError(http.MethodGet, base+"/versions", s.AccessToken, nil, http.StatusNotFound, "not_found")
	e.expectError(http.MethodDelete, base, s.AccessToken, nil, http.StatusNotFound, "not_found")
	e.call(http.MethodGet, "/v1/vaults/"+vaultID+"/trash", s.AccessToken, nil, http.StatusOK, &trash)
	if len(trash.Files) != 0 {
		t.Fatalf("永久删除后回收站应为空")
	}
}

func TestQuota(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.QuotaBytes = 100 })
	s := e.register(uniqueEmail(t)).session
	c1 := newChunkID(t)
	e.putChunk(s.AccessToken, c1, randBytes(t, 80), http.StatusCreated)
	e.expectError(http.MethodPut, "/v1/chunks/"+newChunkID(t), s.AccessToken, randBytes(t, 21), http.StatusRequestEntityTooLarge, "quota_exceeded")
	e.putChunk(s.AccessToken, c1, randBytes(t, 80), http.StatusOK) // 已存在的块不重复计量
	e.putChunk(s.AccessToken, newChunkID(t), randBytes(t, 20), http.StatusCreated)

	var acc service.Account
	e.call(http.MethodGet, "/v1/account", s.AccessToken, nil, http.StatusOK, &acc)
	if acc.Usage.UsedBytes != 100 || acc.Usage.QuotaBytes != 100 {
		t.Fatalf("用量应为 100/100: %+v", acc.Usage)
	}
	if n := e.queryInt(`SELECT count(*) FROM chunks`); n != 2 {
		t.Fatalf("超配额的上传不应登记块,实际 %d 条", n)
	}
}

func TestRetention(t *testing.T) {
	e := newEnv(t, nil)
	s := e.register(uniqueEmail(t)).session
	vaultID := e.createVault(s.AccessToken)
	ctx := context.Background()

	// 版本裁剪:55 个版本 → 保留最近 50 个。
	fileID := newUUID(t)
	for v := int64(0); v < 55; v++ {
		e.commit(s.AccessToken, vaultID, fileID, v, nil, 0, false)
	}
	if _, err := e.app.RunRetention(ctx); err != nil {
		t.Fatal(err)
	}
	if n := e.queryInt(`SELECT count(*) FROM file_versions WHERE file_id = $1`, fileID); n != 50 {
		t.Fatalf("应保留最近 50 个版本,实际 %d", n)
	}
	if n := e.queryInt(`SELECT min(version) FROM file_versions WHERE file_id = $1`, fileID); n != 6 {
		t.Fatalf("应删掉最旧的 5 个版本,最小版本 %d", n)
	}
	// 超过 90 天的历史版本删除,但 head 永远保留。
	e.exec(`UPDATE file_versions SET created_at = now() - interval '91 days' WHERE file_id = $1`, fileID)
	if _, err := e.app.RunRetention(ctx); err != nil {
		t.Fatal(err)
	}
	if n := e.queryInt(`SELECT count(*) FROM file_versions WHERE file_id = $1`, fileID); n != 1 {
		t.Fatalf("90 天前的历史版本应只剩 head,实际 %d", n)
	}
	if n := e.queryInt(`SELECT max(version) FROM file_versions WHERE file_id = $1`, fileID); n != 55 {
		t.Fatalf("保留的应是 head(55),实际 %d", n)
	}

	// 回收站 30 天清空。
	trashed := newUUID(t)
	e.commit(s.AccessToken, vaultID, trashed, 0, nil, 0, false)
	e.commit(s.AccessToken, vaultID, trashed, 1, nil, 0, true)
	if _, err := e.app.RunRetention(ctx); err != nil {
		t.Fatal(err)
	}
	if n := e.queryInt(`SELECT count(*) FROM files WHERE id = $1`, trashed); n != 1 {
		t.Fatalf("未满 30 天的回收站文件应保留")
	}
	e.exec(`UPDATE files SET deleted_at = now() - interval '31 days' WHERE id = $1`, trashed)
	if _, err := e.app.RunRetention(ctx); err != nil {
		t.Fatal(err)
	}
	if n := e.queryInt(`SELECT count(*) FROM files WHERE id = $1`, trashed); n != 0 {
		t.Fatalf("满 30 天的回收站文件应被永久删除")
	}

	// 块回收:无引用且上传超 24 小时才删;被引用的永远不删。
	orphan, referenced := newChunkID(t), newChunkID(t)
	e.putChunk(s.AccessToken, orphan, randBytes(t, 10), http.StatusCreated)
	e.putChunk(s.AccessToken, referenced, randBytes(t, 20), http.StatusCreated)
	e.commit(s.AccessToken, vaultID, newUUID(t), 0, []string{referenced}, 20, false)
	var orphanKey string
	if err := e.app.Pool().QueryRow(ctx, `SELECT object_key FROM chunks WHERE id = $1`, orphan).Scan(&orphanKey); err != nil {
		t.Fatal(err)
	}
	if _, err := e.app.RunRetention(ctx); err != nil {
		t.Fatal(err)
	}
	if n := e.queryInt(`SELECT count(*) FROM chunks`); n != 2 {
		t.Fatalf("宽限期内的块不应回收,剩 %d", n)
	}
	e.exec(`UPDATE chunks SET created_at = now() - interval '25 hours'`)
	res, err := e.app.RunRetention(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Chunks != 1 || res.OrphanedBlobs != 0 {
		t.Fatalf("应回收 1 个块: %+v", res)
	}
	if n := e.queryInt(`SELECT count(*) FROM chunks WHERE id = $1`, referenced); n != 1 {
		t.Fatalf("被引用的块不得回收")
	}
	e.expectError(http.MethodGet, "/v1/chunks/"+orphan, s.AccessToken, nil, http.StatusNotFound, "not_found")
	store, err := blob.Open(ctx, e.cfg.Blob)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := store.Exists(ctx, orphanKey); err != nil || ok {
		t.Fatalf("回收后对象应已删除: ok=%v err=%v", ok, err)
	}
	var acc service.Account
	e.call(http.MethodGet, "/v1/account", s.AccessToken, nil, http.StatusOK, &acc)
	if acc.Usage.UsedBytes != 20 {
		t.Fatalf("回收后用量应扣减到 20,实际 %d", acc.Usage.UsedBytes)
	}
}

func TestDeleteAccountRemovesEverything(t *testing.T) {
	e := newEnv(t, nil)
	u := e.register(uniqueEmail(t))
	s := u.session
	c := newChunkID(t)
	e.putChunk(s.AccessToken, c, randBytes(t, 50), http.StatusCreated)
	vaultID := e.createVault(s.AccessToken)
	e.commit(s.AccessToken, vaultID, newUUID(t), 0, []string{c}, 50, false)
	var key string
	if err := e.app.Pool().QueryRow(context.Background(), `SELECT object_key FROM chunks WHERE id = $1`, c).Scan(&key); err != nil {
		t.Fatal(err)
	}

	e.expectError(http.MethodDelete, "/v1/account", s.AccessToken, map[string]string{"authKey": b64(randBytes(t, 32))}, http.StatusUnauthorized, "unauthorized")
	e.call(http.MethodDelete, "/v1/account", s.AccessToken, map[string]string{"authKey": b64(u.authKey)}, http.StatusNoContent, nil)

	e.expectError(http.MethodGet, "/v1/account", s.AccessToken, nil, http.StatusUnauthorized, "unauthorized")
	e.expectError(http.MethodPost, "/v1/auth/login", "", map[string]any{"email": u.email, "authKey": b64(u.authKey), "device": device("x")}, http.StatusUnauthorized, "unauthorized")
	for _, table := range []string{"users", "devices", "refresh_tokens", "vaults", "files", "file_versions", "chunks", "audit_events"} {
		if n := e.queryInt(`SELECT count(*) FROM ` + table); n != 0 {
			t.Fatalf("删号后 %s 应为空,剩 %d 行", table, n)
		}
	}
	store, err := blob.Open(context.Background(), e.cfg.Blob)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := store.Exists(context.Background(), key); err != nil || ok {
		t.Fatalf("删号后块对象应已删除: ok=%v err=%v", ok, err)
	}
}

func TestEventsWebSocket(t *testing.T) {
	e := newEnv(t, nil)
	s := e.register(uniqueEmail(t)).session
	other := e.register(uniqueEmail(t)).session
	vaultID := e.createVault(s.AccessToken)
	otherVault := e.createVault(other.AccessToken)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	wsURL := "ws" + strings.TrimPrefix(e.srv.URL, "http") + "/v1/events"

	if _, resp, err := websocket.Dial(ctx, wsURL, nil); err == nil || resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("未认证的 WebSocket 握手应 401")
	}

	c, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": []string{"Bearer " + s.AccessToken}},
	})
	if err != nil {
		t.Fatalf("WebSocket 握手: %v", err)
	}
	defer func() { _ = c.CloseNow() }()

	// 监听连接异步建立,首个通知可能早于 LISTEN 生效而丢失;循环提交直到收到为止。
	// 每轮先提交一个别人库里的变更:它不应推给本连接。
	var got struct {
		Type    string `json:"type"`
		VaultID string `json:"vaultId"`
		Seq     int64  `json:"seq"`
	}
	received := false
	for attempt := 0; attempt < 20 && !received; attempt++ {
		e.commit(other.AccessToken, otherVault, newUUID(t), 0, nil, 0, false)
		res := e.commit(s.AccessToken, vaultID, newUUID(t), 0, nil, 0, false)
		rctx, rcancel := context.WithTimeout(ctx, time.Second)
		typ, msg, err := c.Read(rctx)
		rcancel()
		if err != nil {
			if ctx.Err() != nil {
				t.Fatalf("等待通知超时")
			}
			// 单轮读超时会让 coder/websocket 关闭连接,需要重连。
			c, _, err = websocket.Dial(ctx, wsURL, &websocket.DialOptions{
				HTTPHeader: http.Header{"Authorization": []string{"Bearer " + s.AccessToken}},
			})
			if err != nil {
				t.Fatalf("WebSocket 重连: %v", err)
			}
			continue
		}
		if typ != websocket.MessageText {
			t.Fatalf("通知应为文本帧")
		}
		if err := json.Unmarshal(msg, &got); err != nil {
			t.Fatalf("通知不是 JSON: %s", msg)
		}
		if got.Type != "vault.changed" || got.VaultID != vaultID || got.Seq < 1 || got.Seq > res.Seq {
			t.Fatalf("通知内容不符: %+v(最新 seq %d)", got, res.Seq)
		}
		received = true
	}
	if !received {
		t.Fatalf("20 次提交后仍未收到通知")
	}
}
