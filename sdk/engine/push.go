package engine

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ComeHereToSee/typoza-backend/sdk/api"
	"github.com/ComeHereToSee/typoza-backend/sdk/crypto"
	"github.com/ComeHereToSee/typoza-backend/sdk/internal/relpath"
	"github.com/ComeHereToSee/typoza-backend/sdk/internal/uuid"
)

type changeKind int

const (
	changeUpsert changeKind = iota // 新文件、修改、或有待提交的变化
	changeDelete                   // 本地删除
)

// change 是扫描出的一个本地变化。
type change struct {
	kind  changeKind
	path  string
	rec   *fileRecord // 修改/删除:本地记录;新文件为 nil
	info  localInfo   // upsert:扫描时的属性与摘要
	reuse *fileRecord // 改名检测命中:刚消失的旧路径记录,块可直接复用
}

// scan 扫描本地变化(协议 §7.2、§7.7、§7.8)。
func (e *Engine) scan() ([]change, error) {
	records, err := e.store.all()
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	var unreadable []string // 读不了的目录:其下记录不能当作已删除
	var upserts []change
	walkErr := filepath.WalkDir(e.root, func(abs string, d fs.DirEntry, err error) error {
		if err != nil {
			if abs == e.root {
				return err
			}
			if rel, rerr := relpath.FromOS(e.root, abs); rerr == nil {
				unreadable = append(unreadable, rel)
			}
			e.emitErr("", fmt.Errorf("engine: 扫描 %s: %w", abs, err))
			return nil
		}
		if abs == e.root {
			return nil
		}
		rel, err := relpath.FromOS(e.root, abs)
		if err != nil {
			e.emitErr("", fmt.Errorf("engine: 跳过无法同步的文件名 %s: %w", abs, err))
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if e.ign.Match(rel, true) {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || e.ign.Match(rel, false) {
			return nil // 符号链接、设备文件等不同步
		}
		seen[rel] = true
		rec := records[rel]
		info, err := e.inspect(abs, rec)
		if errors.Is(err, errLocalChanged) {
			return nil // 正在写,等下一次
		}
		if err != nil {
			e.emitErr(rel, err)
			return nil
		}
		if !info.st.exists {
			return nil
		}
		if rec != nil && !rec.NeedsCommit && info.hash == rec.ContentHash {
			if !rec.matches(info.st) {
				// 摘要相同只更新 mtime/size(协议 §7.2)。
				rec.MTime, rec.Size = info.st.mtime, info.st.size
				if err := e.store.put(rel, rec); err != nil {
					return err
				}
			}
			return nil
		}
		upserts = append(upserts, change{kind: changeUpsert, path: rel, rec: rec, info: info})
		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("engine: 扫描库目录: %w", walkErr)
	}

	var deletes []change
	for p, rec := range records {
		if seen[p] || e.ign.Match(p, false) || underAny(p, unreadable) {
			continue // 被忽略的路径保持原状,不当作删除
		}
		st, err := statFile(e.abs(p))
		if err != nil {
			e.emitErr(p, err)
			continue
		}
		if st.exists && st.regular {
			continue // 扫描期间刚出现,下次再说
		}
		deletes = append(deletes, change{kind: changeDelete, path: p, rec: rec})
	}

	// 改名检测(协议 §7.7):新路径的摘要等于某个刚消失路径的摘要 → 复用其块,无需重传。
	gone := make(map[string][]*fileRecord)
	for _, d := range deletes {
		if d.rec.Size > 0 {
			gone[d.rec.ContentHash] = append(gone[d.rec.ContentHash], d.rec)
		}
	}
	for i := range upserts {
		u := &upserts[i]
		if u.rec != nil {
			continue
		}
		if cands := gone[u.info.hash]; len(cands) > 0 {
			u.reuse = cands[0]
			gone[u.info.hash] = cands[1:]
		}
	}
	sort.Slice(upserts, func(i, j int) bool { return upserts[i].path < upserts[j].path })
	sort.Slice(deletes, func(i, j int) bool { return deletes[i].path < deletes[j].path })
	// 先提交新内容再提交墓碑:中途中断时服务器上最多多一份,不会少一份。
	return append(upserts, deletes...), nil
}

func underAny(p string, dirs []string) bool {
	for _, d := range dirs {
		if strings.HasPrefix(p, d+"/") {
			return true
		}
	}
	return false
}

// push 扫描并上传本地变化。again=true 表示有提交遇到版本冲突,需要再拉取一轮。
func (e *Engine) push(ctx context.Context) (again bool, fileErrs []error, fatal error) {
	changes, err := e.scan()
	if err != nil {
		return false, nil, err
	}
	for _, ch := range changes {
		var err error
		if ch.kind == changeDelete {
			err = e.pushDelete(ctx, ch)
		} else {
			err = e.pushUpsert(ctx, ch)
		}
		switch {
		case err == nil:
		case api.IsCode(err, api.CodeVersionConflict):
			again = true
		case isFatal(err):
			return false, nil, err
		default:
			fileErrs = append(fileErrs, err)
			e.emitErr(ch.path, err)
		}
	}
	return again, fileErrs, nil
}

func (e *Engine) pushDelete(ctx context.Context, ch change) error {
	if err := e.commitTombstone(ctx, ch.rec.FileID, ch.rec.Version, ch.path); err != nil {
		return fmt.Errorf("engine: 提交 %s 的删除: %w", ch.path, err)
	}
	if err := e.store.remove(ch.path); err != nil {
		return err
	}
	e.emit(Event{Kind: EventSynced, Path: ch.path, Direction: DirectionUp, Reason: "删除"})
	return nil
}

func (e *Engine) pushUpsert(ctx context.Context, ch change) error {
	fileID, base, reason := uuid.New(), int64(0), "新文件"
	if ch.rec != nil {
		fileID, base, reason = ch.rec.FileID, ch.rec.Version, "修改"
	}
	var up *uploaded
	var err error
	switch {
	case ch.reuse != nil:
		reason = "改名(复用已上传的块)"
		up, err = e.reuseContent(ch, ch.reuse)
	case ch.rec != nil && ch.info.hash == ch.rec.ContentHash:
		reason = "路径或版本变化(内容未变)"
		up, err = e.reuseContent(ch, ch.rec)
	default:
		up, err = e.upload(ctx, ch.path)
	}
	if errors.Is(err, errLocalChanged) {
		return nil // 文件还在变,下一次再传
	}
	if err != nil {
		return err
	}
	m := crypto.Manifest{
		Path: ch.path, Size: up.st.size, MTime: time.Unix(0, up.st.mtime),
		ContentHash: up.hash, Chunks: up.chunks,
	}
	res, err := e.commitManifest(ctx, fileID, base, m)
	var ae *api.Error
	if errors.As(err, &ae) && ae.Code == api.CodeMissingChunks {
		// 服务器报告块缺失(检查后被回收,或复用的旧块已不在):补传后重试一次。
		if err := e.uploadMissing(ctx, ch.path, up.chunks, ae.Missing, up.st.size); err != nil {
			if errors.Is(err, errLocalChanged) {
				return nil
			}
			return err
		}
		res, err = e.commitManifest(ctx, fileID, base, m)
	}
	if err != nil {
		return fmt.Errorf("engine: 提交 %s: %w", ch.path, err)
	}
	if err := e.store.put(ch.path, &fileRecord{
		FileID: fileID, Version: res.Version, MTime: up.st.mtime, Size: up.st.size,
		ContentHash: up.hash, Chunks: up.chunks,
	}); err != nil {
		return err
	}
	if up.data != nil {
		if err := e.saveBase(up.hash, up.data); err != nil {
			return err
		}
	}
	e.emit(Event{Kind: EventSynced, Path: ch.path, Direction: DirectionUp, Reason: reason})
	return nil
}

// reuseContent 内容与 src 记录相同(摘要一致即内容一致),直接复用其块列表,不读不传。
// 只有可合并的小文本需要读出全文保存基线。
func (e *Engine) reuseContent(ch change, src *fileRecord) (*uploaded, error) {
	st, err := statFile(e.abs(ch.path))
	if err != nil {
		return nil, err
	}
	if !st.exists || st.size != ch.info.st.size || st.mtime != ch.info.st.mtime {
		return nil, errLocalChanged
	}
	up := &uploaded{st: st, hash: src.ContentHash, chunks: src.Chunks}
	if mergeable(ch.path, st.size) {
		data, err := e.readVerified(e.abs(ch.path), src.ContentHash)
		if err != nil {
			return nil, err
		}
		up.data = data
	}
	return up, nil
}

// commitManifest 加密清单并提交;version = baseVersion + 1(协议 §2.4)。
func (e *Engine) commitManifest(ctx context.Context, fileID string, base int64, m crypto.Manifest) (*api.CommitResult, error) {
	version := base + 1
	blob, err := crypto.EncryptManifest(e.keys.Meta, e.vaultID, fileID, version, m)
	if err != nil {
		return nil, err
	}
	res, err := e.client.Commit(ctx, e.vaultID, fileID, api.CommitRequest{
		BaseVersion: base, Manifest: blob, Chunks: m.Chunks, Size: m.Size, Deleted: m.Deleted,
	})
	if err != nil {
		return nil, err
	}
	if res.Version != version {
		return nil, fmt.Errorf("engine: 服务器返回版本号 %d,预期 %d(清单 AAD 已按 %d 加密)", res.Version, version, version)
	}
	return res, nil
}

// commitTombstone 提交删除墓碑(协议 §2.4:chunks 为空、size=0、contentHash 为空、保留 path)。
func (e *Engine) commitTombstone(ctx context.Context, fileID string, base int64, rel string) error {
	_, err := e.commitManifest(ctx, fileID, base, crypto.Manifest{Path: rel, MTime: time.Now(), Deleted: true})
	return err
}
