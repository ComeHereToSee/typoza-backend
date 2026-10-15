package httpapi

import (
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/ComeHereToSee/typoza-backend/internal/apierr"
	"github.com/ComeHereToSee/typoza-backend/internal/service"
)

func (s *Server) listVaults(w http.ResponseWriter, r *http.Request, p service.Principal) {
	list, err := s.svc.ListVaults(r.Context(), p)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"vaults": list})
}

type createVaultRequest struct {
	ID            string `json:"id"`
	EncryptedName string `json:"encryptedName"`
}

func (s *Server) createVault(w http.ResponseWriter, r *http.Request, p service.Principal) {
	var req createVaultRequest
	if err := decodeJSON(w, r, jsonBodyLimit, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	if err := checkUUID("id", req.ID); err != nil {
		s.writeError(w, r, err)
		return
	}
	if err := checkB64Text("encryptedName", req.EncryptedName, maxVaultNameBytes); err != nil {
		s.writeError(w, r, err)
		return
	}
	v, err := s.svc.CreateVault(r.Context(), p, req.ID, req.EncryptedName)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusCreated, v)
}

// pathVault 读取并校验路径里的 vaultId;失败时已写好错误响应。
func (s *Server) pathVault(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("vaultId")
	if err := checkUUID("vaultId", id); err != nil {
		s.writeError(w, r, err)
		return "", false
	}
	return id, true
}

// pathVaultFile 读取并校验路径里的 vaultId 与 fileId。
func (s *Server) pathVaultFile(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	vaultID, ok := s.pathVault(w, r)
	if !ok {
		return "", "", false
	}
	fileID := r.PathValue("fileId")
	if err := checkUUID("fileId", fileID); err != nil {
		s.writeError(w, r, err)
		return "", "", false
	}
	return vaultID, fileID, true
}

func (s *Server) deleteVault(w http.ResponseWriter, r *http.Request, p service.Principal) {
	vaultID, ok := s.pathVault(w, r)
	if !ok {
		return
	}
	if err := s.svc.DeleteVault(r.Context(), p, vaultID); err != nil {
		s.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type checkChunksRequest struct {
	IDs []string `json:"ids"`
}

func (s *Server) checkChunks(w http.ResponseWriter, r *http.Request, p service.Principal) {
	var req checkChunksRequest
	if err := decodeJSON(w, r, jsonBodyLimit, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	if len(req.IDs) > maxCheckIDs {
		s.writeError(w, r, invalid("ids 一次最多 %d 个", maxCheckIDs))
		return
	}
	if err := checkChunkIDs("ids", req.IDs); err != nil {
		s.writeError(w, r, err)
		return
	}
	missing, err := s.svc.CheckChunks(r.Context(), p, req.IDs)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"missing": missing})
}

// pathChunk 读取并校验路径里的 chunkId。
func (s *Server) pathChunk(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("chunkId")
	if !validChunkID(id) {
		s.writeError(w, r, invalid("chunkId 应为 64 位小写十六进制"))
		return "", false
	}
	return id, true
}

// putChunk 上传块密文:新建 201,已存在 200(幂等),响应体为空。
func (s *Server) putChunk(w http.ResponseWriter, r *http.Request, p service.Principal) {
	id, ok := s.pathChunk(w, r)
	if !ok {
		return
	}
	if r.ContentLength > chunkBodyLimit {
		s.writeError(w, r, apierr.PayloadTooLarge())
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, chunkBodyLimit))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			s.writeError(w, r, apierr.PayloadTooLarge())
			return
		}
		s.writeError(w, r, invalid("读取块内容失败"))
		return
	}
	if len(data) == 0 {
		s.writeError(w, r, invalid("块内容为空"))
		return
	}
	created, err := s.svc.PutChunk(r.Context(), p, id, data)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if created {
		w.WriteHeader(http.StatusCreated)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) getChunk(w http.ResponseWriter, r *http.Request, p service.Principal) {
	id, ok := s.pathChunk(w, r)
	if !ok {
		return
	}
	rc, size, err := s.svc.GetChunk(r.Context(), p, id)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	defer func() {
		if err := rc.Close(); err != nil {
			s.log.Warn("关闭块对象流失败", "chunkId", id, "err", err)
		}
	}()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, rc); err != nil {
		// 状态码已发出,无法再改成错误响应;记录下来,客户端会因长度不足或 HMAC 校验失败而重试。
		s.log.Warn("下发块内容中断", "requestId", requestInfo(r).id, "chunkId", id, "err", err)
	}
}

type commitRequest struct {
	BaseVersion *int64   `json:"baseVersion"`
	Manifest    string   `json:"manifest"`
	Chunks      []string `json:"chunks"`
	Size        *int64   `json:"size"`
	Deleted     bool     `json:"deleted"`
}

func (s *Server) commit(w http.ResponseWriter, r *http.Request, p service.Principal) {
	vaultID, fileID, ok := s.pathVaultFile(w, r)
	if !ok {
		return
	}
	var req commitRequest
	if err := decodeJSON(w, r, commitBodyLimit, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	in, err := req.validate()
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	res, err := s.svc.Commit(r.Context(), p, vaultID, fileID, in)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, res)
}

func (req commitRequest) validate() (service.CommitInput, error) {
	if req.BaseVersion == nil || *req.BaseVersion < 0 {
		return service.CommitInput{}, invalid("baseVersion 必填且不能为负")
	}
	if req.Size == nil || *req.Size < 0 {
		return service.CommitInput{}, invalid("size 必填且不能为负")
	}
	manifest, err := decodeB64("manifest", req.Manifest, 1, maxManifestBytes)
	if err != nil {
		return service.CommitInput{}, err
	}
	if len(req.Chunks) > maxCommitChunks {
		return service.CommitInput{}, invalid("chunks 最多 %d 个", maxCommitChunks)
	}
	if err := checkChunkIDs("chunks", req.Chunks); err != nil {
		return service.CommitInput{}, err
	}
	// 墓碑不引用任何块(协议 §2.4);服务器靠 chunks 做引用计数,这里不一致会让块回收出错。
	if req.Deleted && (len(req.Chunks) > 0 || *req.Size != 0) {
		return service.CommitInput{}, invalid("删除墓碑的 chunks 必须为空且 size 为 0")
	}
	chunks := req.Chunks
	if chunks == nil {
		chunks = []string{}
	}
	return service.CommitInput{
		BaseVersion: *req.BaseVersion,
		Manifest:    manifest,
		Chunks:      chunks,
		Size:        *req.Size,
		Deleted:     req.Deleted,
	}, nil
}

func (s *Server) changes(w http.ResponseWriter, r *http.Request, p service.Principal) {
	vaultID, ok := s.pathVault(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	since := int64(0)
	if v := q.Get("since"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			s.writeError(w, r, invalid("since 应为非负整数"))
			return
		}
		since = n
	}
	limit := defaultChangesLimit
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			s.writeError(w, r, invalid("limit 应为正整数"))
			return
		}
		limit = min(n, maxChangesLimit)
	}
	page, err := s.svc.Changes(r.Context(), p, vaultID, since, limit)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, page)
}

func (s *Server) versions(w http.ResponseWriter, r *http.Request, p service.Principal) {
	vaultID, fileID, ok := s.pathVaultFile(w, r)
	if !ok {
		return
	}
	list, err := s.svc.Versions(r.Context(), p, vaultID, fileID)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"versions": list})
}

func (s *Server) trash(w http.ResponseWriter, r *http.Request, p service.Principal) {
	vaultID, ok := s.pathVault(w, r)
	if !ok {
		return
	}
	list, err := s.svc.Trash(r.Context(), p, vaultID)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"files": list})
}

func (s *Server) purgeFile(w http.ResponseWriter, r *http.Request, p service.Principal) {
	vaultID, fileID, ok := s.pathVaultFile(w, r)
	if !ok {
		return
	}
	if err := s.svc.PurgeFile(r.Context(), p, vaultID, fileID); err != nil {
		s.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
