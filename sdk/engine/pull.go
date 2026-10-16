package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/ComeHereToSee/typoza-backend/sdk/api"
	"github.com/ComeHereToSee/typoza-backend/sdk/crypto"
	"github.com/ComeHereToSee/typoza-backend/sdk/engine/merge"
	"github.com/ComeHereToSee/typoza-backend/sdk/ignore"
)

// SyncNow 立即执行一次完整同步并返回结果。与后台同步串行执行。
// 返回的错误可能是若干文件各自失败的汇总(errors.Join),其余文件照常同步。
func (e *Engine) SyncNow(ctx context.Context) error {
	e.syncMu.Lock()
	defer e.syncMu.Unlock()
	return e.syncLocked(ctx)
}

// syncLocked 需持有 syncMu。
func (e *Engine) syncLocked(ctx context.Context) error {
	e.statusMu.Lock()
	e.status.Syncing = true
	e.statusMu.Unlock()
	e.emit(Event{Kind: EventSyncStarted})

	err := e.runRounds(ctx)

	now := time.Now()
	e.statusMu.Lock()
	e.status.Syncing = false
	e.status.LastSyncAt = now
	e.status.LastError = err
	if err == nil {
		e.status.LastSuccessAt = now
	}
	e.statusMu.Unlock()
	e.emit(Event{Kind: EventSyncFinished, Err: err})
	return err
}

// runRounds 执行「拉取 → 扫描并推送」,提交遇到版本冲突时再来一轮。
func (e *Engine) runRounds(ctx context.Context) error {
	var fileErrs []error
	for round := 0; round < maxRounds; round++ {
		ign, err := ignore.Load(e.root)
		if err != nil {
			return err
		}
		e.ign = ign
		pullErrs, err := e.pull(ctx)
		if err != nil {
			return err
		}
		again, pushErrs, err := e.push(ctx)
		if err != nil {
			return err
		}
		fileErrs = append(pullErrs, pushErrs...)
		if !again {
			if err := e.gcBase(); err != nil {
				fileErrs = append(fileErrs, err)
			}
			return errors.Join(fileErrs...)
		}
	}
	return errors.Join(append(fileErrs, fmt.Errorf("engine: 连续 %d 轮提交都遇到版本冲突,稍后重试", maxRounds))...)
}

// pull 按游标拉取全部变更并逐个落盘(协议 §7.4)。
// 单个文件失败不影响其他文件,但这时不推进游标,下次重新拉取(已处理的版本会按版本号跳过)。
func (e *Engine) pull(ctx context.Context) (fileErrs []error, fatal error) {
	since, err := e.store.cursor()
	if err != nil {
		return nil, err
	}
	var all []api.Version
	cursor := since
	for {
		page, err := e.client.Changes(ctx, e.vaultID, cursor, changesPageSize)
		if err != nil {
			return nil, fmt.Errorf("engine: 拉取变更: %w", err)
		}
		if page.Cursor < cursor {
			return nil, fmt.Errorf("engine: 服务器返回的游标 %d 小于请求的 %d", page.Cursor, cursor)
		}
		all = append(all, page.Changes...)
		advanced := page.Cursor > cursor
		cursor = page.Cursor
		if !page.HasMore {
			break
		}
		if !advanced {
			return nil, fmt.Errorf("engine: 服务器声称还有更多变更但游标停在 %d", cursor)
		}
	}
	// 先处理墓碑、再按 seq 处理其余版本:改名(旧路径墓碑 + 新路径新文件)、
	// 同路径重建等场景下先腾出路径,避免误判成「同一路径两个文件」。
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].Deleted != all[j].Deleted {
			return all[i].Deleted
		}
		return all[i].Seq < all[j].Seq
	})
	for _, v := range all {
		if err := e.applyRemote(ctx, v); err != nil {
			if isFatal(err) {
				return nil, err
			}
			fileErrs = append(fileErrs, err)
			e.emitErr("", err)
		}
	}
	if len(fileErrs) == 0 && cursor != since {
		if err := e.store.setCursor(cursor); err != nil {
			return nil, err
		}
	}
	return fileErrs, nil
}

// applyRemote 把一个远端版本应用到本地。
func (e *Engine) applyRemote(ctx context.Context, v api.Version) error {
	m, err := crypto.DecryptManifest(e.keys.Meta, e.vaultID, v.FileID, v.Version, v.Manifest)
	if err != nil {
		return fmt.Errorf("engine: 文件 %s 版本 %d: %w", v.FileID, v.Version, err)
	}
	if m.Deleted != v.Deleted {
		return fmt.Errorf("engine: 文件 %s 版本 %d 的删除标记与清单不一致", v.FileID, v.Version)
	}
	curPath, rec, err := e.store.byID(v.FileID)
	if err != nil {
		return err
	}
	if rec != nil && rec.Version >= v.Version {
		return nil // 已经是这个版本或更新(含自己刚提交的)
	}
	if m.Deleted {
		return e.applyTombstone(v, curPath, rec)
	}
	if e.ign.Match(m.Path, false) {
		return nil // 本机忽略规则覆盖的路径不落盘
	}
	if rec != nil && curPath != m.Path {
		moved, err := e.applyMove(v, m, curPath, rec)
		if err != nil || moved {
			return err
		}
		rec = nil
	}
	if rec != nil {
		return e.applyUpdate(ctx, v, m, rec)
	}
	return e.applyNew(ctx, v, m)
}

// recordRemote 把落盘后的远端版本写进状态库,可合并文本顺带保存为合并基线。
func (e *Engine) recordRemote(rel string, v api.Version, m crypto.Manifest, st fileStat, needsCommit bool, data []byte) error {
	if err := e.store.put(rel, &fileRecord{
		FileID: v.FileID, Version: v.Version, MTime: st.mtime, Size: st.size,
		ContentHash: m.ContentHash, Chunks: m.Chunks, NeedsCommit: needsCommit,
	}); err != nil {
		return err
	}
	if data != nil {
		return e.saveBase(m.ContentHash, data)
	}
	return nil
}

// applyTombstone 处理远端删除:本地未改 → 交给宿主移入废纸篓;本地有修改 → 保留本地并复活该文件。
func (e *Engine) applyTombstone(v api.Version, curPath string, rec *fileRecord) error {
	if rec == nil {
		return nil // 本地从未有过这个文件
	}
	abs := e.abs(curPath)
	info, err := e.inspect(abs, rec)
	if err != nil {
		return fmt.Errorf("engine: %s: %w", curPath, err)
	}
	switch {
	case !info.st.exists:
		return e.store.remove(curPath)
	case info.hash == rec.ContentHash && !rec.NeedsCommit:
		if err := e.trash(curPath); err != nil {
			return err
		}
		if err := e.store.remove(curPath); err != nil {
			return err
		}
		e.emit(Event{Kind: EventSynced, Path: curPath, Direction: DirectionDown, Reason: "远端已删除,本地文件已移入废纸篓"})
		return nil
	default:
		// 本地有未上传的修改:不丢内容,以墓碑版本为基线重新提交本地内容。
		rec.Version = v.Version
		rec.NeedsCommit = true
		if err := e.store.put(curPath, rec); err != nil {
			return err
		}
		e.emit(Event{Kind: EventConflict, Path: curPath, Reason: "远端已删除但本地有修改,保留本地版本并重新上传"})
		return nil
	}
}

// trash 调宿主钩子把文件移入废纸篓,并确认文件确实已离开原路径。
func (e *Engine) trash(rel string) error {
	abs := e.abs(rel)
	if err := e.trashFn(abs); err != nil {
		return fmt.Errorf("engine: 把 %s 移入废纸篓: %w", rel, err)
	}
	st, err := statFile(abs)
	if err != nil {
		return err
	}
	if st.exists {
		return fmt.Errorf("engine: Trash 钩子返回成功但 %s 仍在原处", rel)
	}
	return nil
}

// applyMove 处理同一 fileId 换了路径(冲突让位等)。本地内容与远端相同且新路径空闲时直接改名;
// 否则按「旧路径删除 + 新路径新文件」处理并返回 moved=false。
func (e *Engine) applyMove(v api.Version, m crypto.Manifest, oldPath string, rec *fileRecord) (moved bool, err error) {
	oldAbs, newAbs := e.abs(oldPath), e.abs(m.Path)
	info, err := e.inspect(oldAbs, rec)
	if err != nil {
		return false, fmt.Errorf("engine: %s: %w", oldPath, err)
	}
	if info.st.exists && info.hash == m.ContentHash {
		target, err := statFile(newAbs)
		if err != nil {
			return false, err
		}
		owner, err := e.store.get(m.Path)
		if err != nil {
			return false, err
		}
		if !target.exists && owner == nil {
			if err := e.ensureParent(m.Path); err != nil {
				return false, err
			}
			if err := os.Rename(oldAbs, newAbs); err != nil {
				return false, fmt.Errorf("engine: 把 %s 改名为 %s: %w", oldPath, m.Path, err)
			}
			st, err := statFile(newAbs)
			if err != nil {
				return false, err
			}
			if err := e.recordRemote(m.Path, v, m, st, false, nil); err != nil {
				return false, err
			}
			e.emit(Event{Kind: EventSynced, Path: m.Path, Direction: DirectionDown, Reason: "远端改名自 " + oldPath})
			return true, nil
		}
	}
	switch {
	case !info.st.exists:
	case info.hash == rec.ContentHash && !rec.NeedsCommit:
		if err := e.trash(oldPath); err != nil {
			return false, err
		}
	default:
		// 旧路径上的本地修改脱离该 fileId,下次扫描作为新文件上传。
	}
	return false, e.store.remove(oldPath)
}

// applyUpdate 处理已同步文件的远端新版本。
func (e *Engine) applyUpdate(ctx context.Context, v api.Version, m crypto.Manifest, rec *fileRecord) error {
	rel := m.Path
	info, err := e.inspect(e.abs(rel), rec)
	if err != nil {
		return fmt.Errorf("engine: %s: %w", rel, err)
	}
	switch {
	case !info.st.exists:
		// 本地删了但远端又改了:远端修改优先(不丢内容),重新落盘,本地删除作废。
		return e.downloadAndRecord(ctx, v, m, rel, expectAbsent(), "远端修改(本地删除已撤销)")
	case info.hash == rec.ContentHash:
		// 本地内容没动过(可能只是有待提交的路径变化,而远端路径与之相同):直接覆盖。
		return e.downloadAndRecord(ctx, v, m, rel, expectStat(info.st), "远端修改")
	case info.hash == m.ContentHash:
		// 本地已经是远端的内容(包括自己上次提交的响应丢失后重试的情形):只采纳版本号。
		return e.adopt(rel, v, m, info)
	default:
		return e.resolveConflict(ctx, v, m, rec, info)
	}
}

// downloadAndRecord 下载落盘并记录;落盘前发现用户刚改过则放弃,下一轮按冲突处理。
func (e *Engine) downloadAndRecord(ctx context.Context, v api.Version, m crypto.Manifest, rel string, ex expect, reason string) error {
	st, data, placed, err := e.download(ctx, rel, m, ex)
	if err != nil || !placed {
		return err
	}
	if err := e.recordRemote(rel, v, m, st, false, data); err != nil {
		return err
	}
	e.emit(Event{Kind: EventSynced, Path: rel, Direction: DirectionDown, Reason: reason})
	return nil
}

// adopt 本地内容已与远端版本相同:只更新记录。
func (e *Engine) adopt(rel string, v api.Version, m crypto.Manifest, info localInfo) error {
	var data []byte
	if mergeable(rel, info.st.size) {
		d, err := e.readVerified(e.abs(rel), m.ContentHash)
		if errors.Is(err, errLocalChanged) {
			return nil
		}
		if err != nil {
			return err
		}
		data = d
	}
	return e.recordRemote(rel, v, m, info.st, false, data)
}

// resolveConflict 本地有未上传修改、远端版本又前进了(协议 §7.5):先尝试三方合并,不行再出冲突副本。
func (e *Engine) resolveConflict(ctx context.Context, v api.Version, m crypto.Manifest, rec *fileRecord, info localInfo) error {
	rel := m.Path
	if mergeable(rel, info.st.size) && mergeable(rel, m.Size) {
		done, err := e.tryMerge(ctx, v, m, rec, info)
		if err != nil || done {
			return err
		}
	}
	return e.conflictCopy(ctx, v, m, info, "双方都修改了该文件")
}

// tryMerge 用上次同步的基线做三方合并;没有基线或有重叠修改时 done=false。
func (e *Engine) tryMerge(ctx context.Context, v api.Version, m crypto.Manifest, rec *fileRecord, info localInfo) (done bool, err error) {
	rel := m.Path
	base, ok, err := e.loadBase(rec.ContentHash)
	if err != nil || !ok {
		return false, err
	}
	local, err := e.readVerified(e.abs(rel), info.hash)
	if errors.Is(err, errLocalChanged) {
		return true, nil // 用户正在改,下一轮再处理
	}
	if err != nil {
		return false, err
	}
	tmp, remote, err := e.fetch(ctx, rel, m)
	if err != nil {
		return false, err
	}
	_ = os.Remove(tmp) // 只需要内容;合并结果另行写入
	merged, ok := merge.Merge3(base, local, remote)
	if !ok {
		return false, nil
	}
	st := info.st
	if !bytes.Equal(merged, local) {
		st, err = e.writeAtomic(rel, merged, time.Time{}, expectStat(info.st))
		if errors.Is(err, errLocalChanged) {
			return true, nil
		}
		if err != nil {
			return false, err
		}
	}
	// 记录指向远端版本(基线 = 远端内容);合并结果与远端不同时标记待提交,由推送阶段上传。
	pending := !bytes.Equal(merged, remote)
	if err := e.recordRemote(rel, v, m, st, pending, remote); err != nil {
		return false, err
	}
	e.emit(Event{Kind: EventConflict, Path: rel, Reason: "双方修改不重叠,已自动合并"})
	return true, nil
}

// conflictCopy 本地内容另存为冲突副本(作为新文件上传),远端版本落到原路径。
// 先复制、再覆盖,任何一步失败都不会丢掉任何一方的内容。
func (e *Engine) conflictCopy(ctx context.Context, v api.Version, m crypto.Manifest, info localInfo, reason string) error {
	rel := m.Path
	cpath, err := e.copyToConflict(rel, info)
	if err != nil || cpath == "" {
		return err
	}
	st, data, placed, err := e.download(ctx, rel, m, expectStat(info.st))
	if err != nil || !placed {
		// 原文件仍是本地内容(或更新的修改),冲突副本多余,删掉它;下一轮重新判断。
		_ = os.Remove(e.abs(cpath))
		return err
	}
	if err := e.recordRemote(rel, v, m, st, false, data); err != nil {
		return err
	}
	e.emit(Event{Kind: EventConflict, Path: rel, ConflictPath: cpath, Reason: reason + ",本地版本已另存为冲突副本"})
	return nil
}

// copyToConflict 把 rel 的当前内容复制到新的冲突副本路径;内容在复制过程中变了返回 ("", nil)。
func (e *Engine) copyToConflict(rel string, info localInfo) (string, error) {
	cpath, err := e.conflictName(rel)
	if err != nil {
		return "", err
	}
	src, err := os.Open(e.abs(rel)) // #nosec G304 -- 同步文件夹里的文件,rel 已校验不越出根目录
	if err != nil {
		return "", fmt.Errorf("engine: 打开 %s: %w", rel, err)
	}
	defer src.Close()
	if err := e.ensureParent(cpath); err != nil {
		return "", err
	}
	tmpf, err := os.CreateTemp(filepath.Dir(e.abs(cpath)), tmpPattern)
	if err != nil {
		return "", fmt.Errorf("engine: 创建临时文件: %w", err)
	}
	tmp := tmpf.Name()
	h := crypto.NewContentHasher(e.keys.ChunkID)
	_, cerr := io.Copy(io.MultiWriter(tmpf, h), src)
	if cerr == nil {
		cerr = tmpf.Sync()
	}
	if err := tmpf.Close(); cerr == nil {
		cerr = err
	}
	if cerr != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("engine: 复制冲突副本: %w", cerr)
	}
	if h.Sum() != info.hash {
		_ = os.Remove(tmp)
		return "", nil
	}
	if _, err := e.place(tmp, cpath, expectAbsent()); err != nil {
		if errors.Is(err, errLocalChanged) {
			return "", nil
		}
		return "", err
	}
	return cpath, nil
}

// applyNew 处理本地没有记录的 fileId。
func (e *Engine) applyNew(ctx context.Context, v api.Version, m crypto.Manifest) error {
	rel := m.Path
	owner, err := e.store.get(rel)
	if err != nil {
		return err
	}
	info, err := e.inspect(e.abs(rel), owner)
	if err != nil {
		return fmt.Errorf("engine: %s: %w", rel, err)
	}
	if owner == nil {
		switch {
		case !info.st.exists:
			return e.downloadAndRecord(ctx, v, m, rel, expectAbsent(), "远端新文件")
		case info.hash == m.ContentHash:
			return e.adopt(rel, v, m, info)
		default:
			// 本地同路径有个还没上传的新文件,内容不同,没有基线可合并。
			return e.conflictCopy(ctx, v, m, info, "本地与远端各自新建了同名文件")
		}
	}
	return e.resolvePathClash(ctx, v, m, owner, info)
}

// resolvePathClash 同一路径被两个 fileId 占用:fileId 字典序较小者保留路径。
func (e *Engine) resolvePathClash(ctx context.Context, v api.Version, m crypto.Manifest, owner *fileRecord, info localInfo) error {
	rel := m.Path
	sameContent := info.st.exists && info.hash == m.ContentHash
	if v.FileID < owner.FileID {
		// 远端胜出,本地 owner 让位。
		if sameContent || !info.st.exists {
			// 内容相同(或本地已删):为 owner 提交墓碑,本地直接归属远端文件。
			if err := e.commitTombstone(ctx, owner.FileID, owner.Version, rel); err != nil {
				if api.IsCode(err, api.CodeVersionConflict) {
					return nil // owner 在远端又变了,下一轮重新判断
				}
				return err
			}
			if !info.st.exists {
				if err := e.store.remove(rel); err != nil {
					return err
				}
				return e.downloadAndRecord(ctx, v, m, rel, expectAbsent(), "远端新文件")
			}
			return e.adopt(rel, v, m, info)
		}
		cpath, err := e.conflictName(rel)
		if err != nil {
			return err
		}
		if err := os.Rename(e.abs(rel), e.abs(cpath)); err != nil {
			return fmt.Errorf("engine: 把 %s 让位改名为 %s: %w", rel, cpath, err)
		}
		st, err := statFile(e.abs(cpath))
		if err != nil {
			return err
		}
		moved := *owner
		moved.MTime, moved.Size, moved.NeedsCommit = st.mtime, st.size, true
		if err := e.store.put(cpath, &moved); err != nil {
			return err
		}
		if err := e.downloadAndRecord(ctx, v, m, rel, expectAbsent(), "远端新文件"); err != nil {
			return err
		}
		e.emit(Event{Kind: EventConflict, Path: rel, ConflictPath: cpath, Reason: "两台设备各自新建了同名文件,本地文件已改名为冲突副本"})
		return nil
	}
	// 本地胜出,远端文件让位。
	if sameContent {
		if err := e.commitTombstone(ctx, v.FileID, v.Version, rel); err != nil && !api.IsCode(err, api.CodeVersionConflict) {
			return err
		}
		return nil
	}
	cpath, err := e.conflictName(rel)
	if err != nil {
		return err
	}
	st, data, placed, err := e.download(ctx, cpath, m, expectAbsent())
	if err != nil || !placed {
		return err
	}
	// 记录在新路径上、标记待提交:推送阶段以该 fileId 提交新路径,其他设备据此改名。
	if err := e.recordRemote(cpath, v, m, st, true, data); err != nil {
		return err
	}
	e.emit(Event{Kind: EventConflict, Path: rel, ConflictPath: cpath, Reason: "两台设备各自新建了同名文件,远端文件已另存为冲突副本"})
	return nil
}
