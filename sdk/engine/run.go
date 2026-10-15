package engine

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/ComeHereToSee/typoza-backend/sdk/api"
	"github.com/ComeHereToSee/typoza-backend/sdk/ignore"
	"github.com/ComeHereToSee/typoza-backend/sdk/internal/relpath"
)

// Start 启动后台同步并立即返回:先同步一次,之后
//   - 本地文件变化:递归监听库目录,1 秒去抖后同步;
//   - 服务器推送 vault.changed:立即同步;事件连接(重)建立后补拉一次;
//   - 每 5 分钟兜底轮询一次。
//
// ctx 取消或调用 Close 时停止。每个 Engine 只能 Start 一次。
func (e *Engine) Start(ctx context.Context) error {
	e.runMu.Lock()
	defer e.runMu.Unlock()
	if e.closed {
		return errors.New("engine: 已关闭")
	}
	if e.started {
		return errors.New("engine: 已经启动")
	}
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("engine: 创建文件监听: %w", err)
	}
	// 监听过滤只用启动时的规则:规则文件之后再变也只是多触发几次廉价的同步。
	ign, err := ignore.Load(e.root)
	if err != nil {
		_ = w.Close()
		return err
	}
	if err := e.watchTree(w, ign, e.root); err != nil {
		_ = w.Close()
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	e.cancel = cancel
	e.started = true
	e.wg.Add(3)
	go e.syncLoop(ctx)
	go e.watchLoop(ctx, w, ign)
	go e.eventsLoop(ctx)
	e.requestSync()
	return nil
}

// requestSync 请求后台尽快同步一次;已有待处理请求时合并。
func (e *Engine) requestSync() {
	select {
	case e.trigger <- struct{}{}:
	default:
	}
}

func (e *Engine) syncLoop(ctx context.Context) {
	defer e.wg.Done()
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-e.trigger:
		case <-ticker.C:
		}
		e.syncMu.Lock()
		// 结果已通过 EventSyncFinished 与 Status 上报;失败不退出,等下一次触发重试。
		_ = e.syncLocked(ctx)
		e.syncMu.Unlock()
	}
}

func (e *Engine) eventsLoop(ctx context.Context) {
	defer e.wg.Done()
	err := e.client.SubscribeEvents(ctx, api.EventHandlers{
		OnEvent: func(ev api.Event) {
			if ev.Type == api.EventVaultChanged && ev.VaultID == e.vaultID {
				e.requestSync()
			}
		},
		OnReconnect: e.requestSync,
		OnError: func(err error) {
			e.emitErr("", fmt.Errorf("engine: 实时通知连接: %w", err))
		},
	})
	if err != nil && ctx.Err() == nil {
		// 登录态失效等无法自动恢复的情况;兜底轮询仍在,但同样会失败并上报。
		e.emitErr("", fmt.Errorf("engine: 实时通知已停止: %w", err))
	}
}

// watchTree 为 dir 及其下所有未被忽略的子目录添加监听(fsnotify 不递归)。
func (e *Engine) watchTree(w *fsnotify.Watcher, ign *ignore.Matcher, dir string) error {
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == dir {
				return fmt.Errorf("engine: 监听 %s: %w", p, err)
			}
			e.emitErr("", fmt.Errorf("engine: 监听 %s: %w", p, err))
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		if p != e.root {
			rel, err := relpath.FromOS(e.root, p)
			if err != nil || ign.Match(rel, true) {
				return fs.SkipDir
			}
		}
		if err := w.Add(p); err != nil {
			if p == dir {
				return fmt.Errorf("engine: 监听 %s: %w", p, err)
			}
			e.emitErr("", fmt.Errorf("engine: 监听 %s: %w", p, err))
		}
		return nil
	})
}

func (e *Engine) watchLoop(ctx context.Context, w *fsnotify.Watcher, ign *ignore.Matcher) {
	defer e.wg.Done()
	defer w.Close()
	timer := time.NewTimer(debounceDelay)
	timer.Stop()
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-w.Events:
			if !ok {
				return
			}
			if ev.Op == fsnotify.Chmod {
				continue // Spotlight、备份软件等只改属性,不算内容变化
			}
			rel, err := relpath.FromOS(e.root, ev.Name)
			if err != nil || ign.Match(rel, false) {
				continue
			}
			if ev.Has(fsnotify.Create) {
				if fi, err := os.Lstat(ev.Name); err == nil && fi.IsDir() && !ign.Match(rel, true) {
					// 新建的目录要补加监听;目录可能是整棵搬进来的,递归处理。
					if err := e.watchTree(w, ign, ev.Name); err != nil {
						e.emitErr(rel, err)
					}
				}
			}
			// Go 1.23 起 Reset 不会收到过期的触发,可直接重置去抖计时器。
			timer.Reset(debounceDelay)
		case err, ok := <-w.Errors:
			if !ok {
				return
			}
			e.emitErr("", fmt.Errorf("engine: 文件监听: %w", err))
		case <-timer.C:
			e.requestSync()
		}
	}
}
