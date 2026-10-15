package engine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ComeHereToSee/typoza-backend/sdk/api"
	"github.com/ComeHereToSee/typoza-backend/sdk/crypto"
	"github.com/ComeHereToSee/typoza-backend/sdk/internal/relpath"
	"github.com/ComeHereToSee/typoza-backend/sdk/internal/uuid"
)

// ErrNotTracked 表示路径从未同步过(状态库里没有记录)。
var ErrNotTracked = errors.New("engine: 该路径尚未同步,没有云端记录")

// ErrTooLarge 表示要读取的版本内容超过调用方给的上限。
var ErrTooLarge = errors.New("engine: 版本内容超过读取上限")

// VersionInfo 是一个历史版本(清单已解密)。
type VersionInfo struct {
	FileID      string
	Version     int64
	Path        string
	Size        int64
	MTime       time.Time
	ContentHash string
	Deleted     bool
	DeviceID    string
	CreatedAt   time.Time
}

// TrashItem 是回收站中的一个文件。
type TrashItem struct {
	FileID string
	// Path 是删除前的路径。
	Path      string
	Version   int64
	DeletedAt time.Time
}

// Versions 列出 path 对应文件的历史版本(新→旧)。
func (e *Engine) Versions(ctx context.Context, path string) ([]VersionInfo, error) {
	rel, err := relpath.Clean(path)
	if err != nil {
		return nil, err
	}
	rec, err := e.store.get(rel)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, fmt.Errorf("%w: %s", ErrNotTracked, rel)
	}
	infos, _, err := e.versionsOf(ctx, rec.FileID)
	return infos, err
}

// versionsOf 拉取并解密某文件的全部版本(新→旧)。
func (e *Engine) versionsOf(ctx context.Context, fileID string) ([]VersionInfo, []crypto.Manifest, error) {
	vers, err := e.client.Versions(ctx, e.vaultID, fileID)
	if err != nil {
		return nil, nil, fmt.Errorf("engine: 获取文件 %s 的历史版本: %w", fileID, err)
	}
	if len(vers) == 0 {
		return nil, nil, fmt.Errorf("engine: 文件 %s 没有任何版本", fileID)
	}
	infos := make([]VersionInfo, 0, len(vers))
	mans := make([]crypto.Manifest, 0, len(vers))
	for i, v := range vers {
		if v.FileID != fileID || (i > 0 && v.Version >= vers[i-1].Version) {
			return nil, nil, fmt.Errorf("engine: 服务器返回的版本列表异常(文件 %s)", fileID)
		}
		m, err := crypto.DecryptManifest(e.keys.Meta, e.vaultID, fileID, v.Version, v.Manifest)
		if err != nil {
			return nil, nil, fmt.Errorf("engine: 文件 %s 版本 %d: %w", fileID, v.Version, err)
		}
		infos = append(infos, VersionInfo{
			FileID: fileID, Version: v.Version, Path: m.Path, Size: m.Size, MTime: m.MTime,
			ContentHash: m.ContentHash, Deleted: m.Deleted, DeviceID: v.DeviceID, CreatedAt: v.CreatedAt,
		})
		mans = append(mans, m)
	}
	return infos, mans, nil
}

// Restore 把 path 恢复到历史版本 version:用旧清单内容、以当前版本为 baseVersion 重新提交
// (清单按新版本号重新加密,协议 §4.4),然后同步一次把它落到本地。
// 本地若有未上传的修改,按常规冲突规则处理(合并或冲突副本),不会丢失。
func (e *Engine) Restore(ctx context.Context, path string, version int64) error {
	rel, err := relpath.Clean(path)
	if err != nil {
		return err
	}
	e.syncMu.Lock()
	defer e.syncMu.Unlock()
	rec, err := e.store.get(rel)
	if err != nil {
		return err
	}
	if rec == nil {
		return fmt.Errorf("%w: %s", ErrNotTracked, rel)
	}
	infos, mans, err := e.versionsOf(ctx, rec.FileID)
	if err != nil {
		return err
	}
	idx := -1
	for i, info := range infos {
		if info.Version == version {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("engine: %s 没有版本 %d(可能已超出保留期)", rel, version)
	}
	if infos[idx].Deleted {
		return fmt.Errorf("engine: %s 的版本 %d 是删除记录,不能恢复为该版本", rel, version)
	}
	if idx == 0 {
		return nil // 已经是当前版本
	}
	if err := e.recommit(ctx, rec.FileID, infos[0], mans[idx]); err != nil {
		return err
	}
	return e.syncLocked(ctx)
}

// ReadVersion 下载并解密 path 的历史版本 version 的完整内容,只放在内存里、不落盘,
// 供宿主预览或比对。内容超过 maxBytes 时不下载,返回 ErrTooLarge。
func (e *Engine) ReadVersion(ctx context.Context, path string, version, maxBytes int64) ([]byte, error) {
	rel, err := relpath.Clean(path)
	if err != nil {
		return nil, err
	}
	rec, err := e.store.get(rel)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, fmt.Errorf("%w: %s", ErrNotTracked, rel)
	}
	infos, mans, err := e.versionsOf(ctx, rec.FileID)
	if err != nil {
		return nil, err
	}
	for i, info := range infos {
		if info.Version != version {
			continue
		}
		if info.Deleted {
			return nil, fmt.Errorf("engine: %s 的版本 %d 是删除记录,没有内容", rel, version)
		}
		m := mans[i]
		if m.Size > maxBytes {
			return nil, fmt.Errorf("%w: %s 版本 %d 有 %d 字节", ErrTooLarge, rel, version, m.Size)
		}
		buf := make([]byte, m.Size)
		err := e.downloadChunks(ctx, rel, m, func(off int64, plain []byte) error {
			copy(buf[off:], plain)
			return nil
		})
		if err != nil {
			return nil, err
		}
		if crypto.ContentHash(e.keys.ChunkID, buf) != m.ContentHash {
			return nil, fmt.Errorf("engine: %s 版本 %d 的内容摘要与清单不符(数据被篡改)", rel, version)
		}
		return buf, nil
	}
	return nil, fmt.Errorf("engine: %s 没有版本 %d(可能已超出保留期)", rel, version)
}

// recommit 以 head 为 baseVersion 重新提交旧内容 m;路径沿用 head 的路径。
func (e *Engine) recommit(ctx context.Context, fileID string, head VersionInfo, m crypto.Manifest) error {
	m.Path = head.Path
	m.MTime = time.Now()
	if _, err := e.commitManifest(ctx, fileID, head.Version, m); err != nil {
		return fmt.Errorf("engine: 恢复 %s: %w", head.Path, err)
	}
	return nil
}

// Trash 列出回收站中的文件(删除前的路径来自墓碑清单)。
func (e *Engine) Trash(ctx context.Context) ([]TrashItem, error) {
	entries, err := e.client.Trash(ctx, e.vaultID)
	if err != nil {
		return nil, fmt.Errorf("engine: 获取回收站: %w", err)
	}
	items := make([]TrashItem, 0, len(entries))
	for _, t := range entries {
		m, err := crypto.DecryptManifest(e.keys.Meta, e.vaultID, t.FileID, t.Version, t.Manifest)
		if err != nil {
			return nil, fmt.Errorf("engine: 回收站文件 %s: %w", t.FileID, err)
		}
		items = append(items, TrashItem{FileID: t.FileID, Path: m.Path, Version: t.Version, DeletedAt: t.DeletedAt})
	}
	return items, nil
}

// RestoreFromTrash 把回收站中的文件恢复为删除前的最后一个版本,然后同步一次把它落到本地。
// 原路径已被别的文件占用时按「同一路径两个文件」规则处理,恢复出的内容不会丢。
func (e *Engine) RestoreFromTrash(ctx context.Context, fileID string) error {
	if !uuid.Valid(fileID) {
		return fmt.Errorf("engine: fileId %q 不是小写 UUID", fileID)
	}
	e.syncMu.Lock()
	defer e.syncMu.Unlock()
	infos, mans, err := e.versionsOf(ctx, fileID)
	if err != nil {
		return err
	}
	if !infos[0].Deleted {
		return fmt.Errorf("engine: 文件 %s(%s)不在回收站", fileID, infos[0].Path)
	}
	for i := 1; i < len(infos); i++ {
		if !infos[i].Deleted {
			if err := e.recommit(ctx, fileID, infos[0], mans[i]); err != nil {
				return err
			}
			return e.syncLocked(ctx)
		}
	}
	return fmt.Errorf("engine: 文件 %s 没有可恢复的内容版本(可能已超出保留期)", fileID)
}

// Purge 永久删除回收站中的文件(仅限已删除文件,否则服务器返回 not_deleted)。
func (e *Engine) Purge(ctx context.Context, fileID string) error {
	if err := e.client.PurgeFile(ctx, e.vaultID, fileID); err != nil {
		return fmt.Errorf("engine: 永久删除 %s: %w", fileID, err)
	}
	return nil
}

// VaultInfo 是一个库(名称已解密)。
type VaultInfo struct {
	ID        string
	Name      string
	CreatedAt time.Time
}

// CreateVault 创建库:本机生成 vaultId,库名用 metaKey 加密后提交。
func CreateVault(ctx context.Context, c *api.Client, keys *crypto.Keys, name string) (*VaultInfo, error) {
	id := uuid.New()
	enc, err := crypto.EncryptVaultName(keys.Meta, id, name)
	if err != nil {
		return nil, err
	}
	v, err := c.CreateVault(ctx, id, enc)
	if err != nil {
		return nil, fmt.Errorf("engine: 创建库: %w", err)
	}
	return &VaultInfo{ID: v.ID, Name: name, CreatedAt: v.CreatedAt}, nil
}

// ListVaults 列出账号下的库并解密库名。
func ListVaults(ctx context.Context, c *api.Client, keys *crypto.Keys) ([]VaultInfo, error) {
	vs, err := c.Vaults(ctx)
	if err != nil {
		return nil, fmt.Errorf("engine: 列出库: %w", err)
	}
	out := make([]VaultInfo, 0, len(vs))
	for _, v := range vs {
		name, err := crypto.DecryptVaultName(keys.Meta, v.ID, v.EncryptedName)
		if err != nil {
			return nil, err
		}
		out = append(out, VaultInfo{ID: v.ID, Name: name, CreatedAt: v.CreatedAt})
	}
	return out, nil
}
