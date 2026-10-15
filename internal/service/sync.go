package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/ComeHereToSee/typoza-backend/internal/apierr"
	"github.com/ComeHereToSee/typoza-backend/internal/blob"
	"github.com/ComeHereToSee/typoza-backend/internal/store"
)

// ListVaults 列出账号下的库。
func (s *Service) ListVaults(ctx context.Context, p Principal) ([]Vault, error) {
	list, err := s.store.ListVaults(ctx, p.UserID)
	if err != nil {
		return nil, err
	}
	out := make([]Vault, 0, len(list))
	for _, v := range list {
		out = append(out, vaultDTO(v))
	}
	return out, nil
}

// CreateVault 创建库(ID 由客户端生成)。
func (s *Service) CreateVault(ctx context.Context, p Principal, vaultID, encryptedName string) (Vault, error) {
	v, err := s.store.CreateVault(ctx, p.UserID, vaultID, encryptedName)
	if errors.Is(err, store.ErrVaultExists) {
		return Vault{}, errVaultExists
	}
	if err != nil {
		return Vault{}, err
	}
	return vaultDTO(v), nil
}

// DeleteVault 删除库及其全部清单;块由后台回收任务清理。
func (s *Service) DeleteVault(ctx context.Context, p Principal, vaultID string) error {
	return vaultErr(s.store.DeleteVault(ctx, p.UserID, vaultID))
}

// CheckChunks 返回 ids 中尚未上传的块(去重,保持请求顺序)。
func (s *Service) CheckChunks(ctx context.Context, p Principal, ids []string) ([]string, error) {
	have, err := s.store.ExistingChunks(ctx, p.UserID, ids)
	if err != nil {
		return nil, err
	}
	missing := []string{}
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if !have[id] && !seen[id] {
			missing = append(missing, id)
		}
		seen[id] = true
	}
	return missing, nil
}

// PutChunk 上传块密文;已存在时不重复存储(幂等)。返回是否新建。
//
// 对象键带随机后缀(chunks/<userId>/<chunkId>-<16 位十六进制>):同一块被并发上传、或与块回收交错时,
// 各自写的是不同对象,不会出现一方删掉另一方刚写入对象的情况。
func (s *Service) PutChunk(ctx context.Context, p Principal, chunkID string, data []byte) (bool, error) {
	size := int64(len(data))
	if _, _, err := s.store.ChunkObject(ctx, p.UserID, chunkID); err == nil {
		return false, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return false, err
	}
	// 预检配额,避免为注定失败的上传写对象;最终以 InsertChunk 里的条件更新为准。
	used, quota, err := s.store.Usage(ctx, p.UserID)
	if err != nil {
		return false, err
	}
	if used+size > quota {
		return false, errQuotaExceeded
	}

	key := "chunks/" + p.UserID + "/" + chunkID + "-" + randomHex(8)
	if err := s.blobs.Put(ctx, key, bytes.NewReader(data), size); err != nil {
		return false, err
	}
	inserted, err := s.store.InsertChunk(ctx, p.UserID, chunkID, size, key)
	if err != nil || !inserted {
		// 没登记成功(超配额、并发上传先登记、或出错):删掉刚写的对象。
		s.deleteObjects(ctx, []string{key})
	}
	if errors.Is(err, store.ErrQuotaExceeded) {
		return false, errQuotaExceeded
	}
	if err != nil {
		return false, err
	}
	return inserted, nil
}

// GetChunk 返回块密文流与大小;块不存在或属于其他账号时返回 404。
func (s *Service) GetChunk(ctx context.Context, p Principal, chunkID string) (io.ReadCloser, int64, error) {
	key, _, err := s.store.ChunkObject(ctx, p.UserID, chunkID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, 0, apierr.NotFound("块不存在")
	}
	if err != nil {
		return nil, 0, err
	}
	rc, size, err := s.blobs.Get(ctx, key)
	if errors.Is(err, blob.ErrNotFound) {
		// 有记录没对象是服务端数据不一致,按内部错误处理并留下足够的排查线索。
		return nil, 0, fmt.Errorf("块 %s 有记录但对象 %s 不存在: %w", chunkID, key, err)
	}
	if err != nil {
		return nil, 0, err
	}
	return rc, size, nil
}

// CommitInput 是文件提交请求。
type CommitInput struct {
	BaseVersion int64
	Manifest    []byte
	Chunks      []string
	Size        int64
	Deleted     bool
}

// Commit 提交文件新版本(协议 §4.4)。
func (s *Service) Commit(ctx context.Context, p Principal, vaultID, fileID string, in CommitInput) (CommitResult, error) {
	res, err := s.store.Commit(ctx, store.CommitInput{
		UserID:      p.UserID,
		DeviceID:    p.DeviceID,
		VaultID:     vaultID,
		FileID:      fileID,
		BaseVersion: in.BaseVersion,
		Manifest:    in.Manifest,
		Chunks:      in.Chunks,
		Size:        in.Size,
		Deleted:     in.Deleted,
	})
	var conflict *store.ConflictError
	var missing *store.MissingChunksError
	switch {
	case errors.As(err, &conflict):
		// 文件不存在(例如已被永久删除)时 head 为 null,客户端应按新文件(baseVersion=0)重新提交。
		var head *Version
		if conflict.Head != nil {
			v := versionDTO(*conflict.Head)
			head = &v
		}
		return CommitResult{}, errVersionConflict.With("head", head)
	case errors.As(err, &missing):
		return CommitResult{}, errMissingChunks.With("missing", missing.IDs)
	case err != nil:
		return CommitResult{}, vaultErr(err)
	}
	return CommitResult{Version: res.Version, Seq: res.Seq}, nil
}

// Changes 返回 since 之后的变更页。cursor = 本页最后一条的 seq,无变化时等于 since。
func (s *Service) Changes(ctx context.Context, p Principal, vaultID string, since int64, limit int) (ChangesPage, error) {
	list, hasMore, err := s.store.Changes(ctx, p.UserID, vaultID, since, limit)
	if err != nil {
		return ChangesPage{}, vaultErr(err)
	}
	cursor := since
	if len(list) > 0 {
		cursor = list[len(list)-1].Seq
	}
	return ChangesPage{Changes: versionDTOs(list), Cursor: cursor, HasMore: hasMore}, nil
}

// Versions 返回文件的历史版本(新 → 旧)。
func (s *Service) Versions(ctx context.Context, p Principal, vaultID, fileID string) ([]Version, error) {
	list, err := s.store.Versions(ctx, p.UserID, vaultID, fileID)
	if errors.Is(err, store.ErrNotFound) {
		// 区分「库不存在」与「文件不存在」对客户端没有意义,统一 404。
		return nil, apierr.NotFound("文件或库不存在")
	}
	if err != nil {
		return nil, vaultErr(err)
	}
	return versionDTOs(list), nil
}

// Trash 返回库回收站。
func (s *Service) Trash(ctx context.Context, p Principal, vaultID string) ([]TrashItem, error) {
	list, err := s.store.Trash(ctx, p.UserID, vaultID)
	if err != nil {
		return nil, vaultErr(err)
	}
	out := make([]TrashItem, 0, len(list))
	for _, t := range list {
		out = append(out, TrashItem{FileID: t.FileID, Version: t.Version, Manifest: b64(t.Manifest), DeletedAt: formatTime(t.DeletedAt)})
	}
	return out, nil
}

// PurgeFile 永久删除回收站里的文件。
func (s *Service) PurgeFile(ctx context.Context, p Principal, vaultID, fileID string) error {
	err := s.store.PurgeFile(ctx, p.UserID, vaultID, fileID)
	switch {
	case errors.Is(err, store.ErrNotDeleted):
		return errNotDeleted
	case errors.Is(err, store.ErrNotFound):
		return apierr.NotFound("文件或库不存在")
	}
	return vaultErr(err)
}
