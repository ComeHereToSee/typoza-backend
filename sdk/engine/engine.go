// Package engine 是 Typoza 客户端同步引擎,实现 sync-protocol §7 的全部规范性要求。
//
// 一个 Engine 管一个库:本地根目录 + vaultId + 解锁后的密钥 + api.Client + 状态库。
// 典型用法(宿主辅助进程):
//
//	e, err := engine.New(engine.Options{Root: ..., StateDir: ..., VaultID: ..., Keys: sess.Keys,
//	    Client: client, DeviceName: "Z 的 MacBook Pro", Trash: moveToTrash, OnEvent: report})
//	err = e.Start(ctx)        // 后台:本地监听(1 秒去抖)+ 服务器推送 + 5 分钟兜底轮询
//	err = e.SyncNow(ctx)      // 「立即同步」
//	st := e.Status()
//	err = e.Close()           // 停止后台任务并关闭状态库
//
// 一轮同步 = 拉取远端变更并落盘(含冲突处理)→ 扫描本地变化并上传提交;提交遇到版本冲突时
// 再来一轮(最多 4 轮)。引擎绝不直接删除用户文件:远端删除通过宿主提供的 Trash 钩子移入废纸篓。
//
// 冲突处理(本地有未上传修改、远端版本又前进了):
//   - .md/.markdown/.txt 且 ≤ 2 MiB、并保存了上次同步的基线内容 → 行级三方合并,无重叠修改则自动合并;
//   - 否则远端版本落到原路径,本地版本另存为「原名 (冲突副本 <设备名> <YYYY-MM-DD HHmm>).扩展名」并作为新文件上传。
//
// 同一路径被两个不同 fileId 占用(两台设备离线时各自新建了同名文件)时,
// 按 fileId 字典序较小者保留原路径、较大者改名为冲突副本;内容相同时为较大者提交墓碑。
// 各设备独立得出相同结论,并发处理由服务器的版本冲突检测收敛。
package engine

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ComeHereToSee/typoza-backend/sdk/api"
	"github.com/ComeHereToSee/typoza-backend/sdk/crypto"
	"github.com/ComeHereToSee/typoza-backend/sdk/ignore"
	"github.com/ComeHereToSee/typoza-backend/sdk/internal/uuid"
)

// 引擎的固定参数(协议 §7 与任务约定)。
const (
	// mergeMaxSize:可三方合并的文本文件大小上限,也是保存合并基线的上限。
	mergeMaxSize = 2 << 20
	// transferConcurrency:块上传、下载的并发上限。
	transferConcurrency = 4
	// changesPageSize:每次拉取变更的条数。
	changesPageSize = 500
	// maxRounds:一次同步最多「拉取 + 推送」的轮数(提交冲突时再来一轮)。
	maxRounds = 4
	// debounceDelay:本地文件变化的去抖间隔。
	debounceDelay = time.Second
	// pollInterval:兜底轮询间隔。
	pollInterval = 5 * time.Minute
	// stateDirName:状态目录放在库内时必须用这个名字(内置忽略规则 .typoza/ 覆盖它)。
	stateDirName = ".typoza"
)

// mergeableExts 是可做三方合并的文本扩展名(协议 §7.5)。
var mergeableExts = map[string]bool{".md": true, ".markdown": true, ".txt": true}

// Options 是 Engine 的构造参数。除 OnEvent 外均为必填。
type Options struct {
	// Root 是本地库根目录的绝对路径,必须已存在。
	Root string
	// StateDir 是该库专用的状态目录(状态库 state.db 与合并基线 base/),不存在时自动创建。
	// 建议放在应用支持目录;放在库内时必须是 <Root>/.typoza。
	StateDir string
	// VaultID 是库 ID(小写 UUID),见 CreateVault / ListVaults。
	VaultID string
	// Keys 是解锁后的数据密钥(account.Login 等的返回值)。
	Keys *crypto.Keys
	// Client 是已登录的 api.Client。
	Client *api.Client
	// DeviceName 用于冲突副本命名。
	DeviceName string
	// Trash 由宿主实现:把 absPath 指向的文件移进系统废纸篓。引擎自己从不删除用户文件。
	Trash func(absPath string) error
	// OnEvent 接收进度、已同步、冲突、错误等事件;引擎保证串行调用,回调应尽快返回。
	OnEvent func(Event)
}

// Engine 是单个库的同步引擎。方法可被多个 goroutine 并发调用。
type Engine struct {
	root       string
	stateDir   string
	vaultID    string
	deviceName string
	keys       *crypto.Keys
	client     *api.Client
	trashFn    func(string) error
	onEvent    func(Event)
	store      *store
	now        func() time.Time // 冲突副本命名用的时钟;测试里替换成固定时间

	// syncMu 串行化所有会改动本地文件或提交的操作(同步、历史恢复、回收站恢复)。
	syncMu sync.Mutex
	// ign 是本轮同步使用的忽略规则,只在持有 syncMu 时读写。
	ign *ignore.Matcher

	trigger chan struct{}

	emitMu sync.Mutex

	statusMu sync.Mutex
	status   Status

	runMu   sync.Mutex
	started bool
	closed  bool
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// Status 是引擎状态快照。
type Status struct {
	// Syncing 表示正在同步。
	Syncing bool
	// LastSyncAt 是上一次同步(无论成败)结束的时间。
	LastSyncAt time.Time
	// LastSuccessAt 是上一次完全成功的同步结束的时间。
	LastSuccessAt time.Time
	// LastError 是上一次同步的错误;成功时为 nil。
	LastError error
}

// EventKind 是事件类型。
type EventKind string

const (
	// EventSyncStarted:一次同步开始。
	EventSyncStarted EventKind = "sync_started"
	// EventSyncFinished:一次同步结束;Err 非空表示失败或部分文件失败。
	EventSyncFinished EventKind = "sync_finished"
	// EventProgress:单个文件的传输进度;Bytes/Total 为已传/总字节数(明文)。
	EventProgress EventKind = "progress"
	// EventSynced:单个文件已同步(上传或落盘);Reason 说明是新建、修改、删除还是改名。
	EventSynced EventKind = "synced"
	// EventConflict:发生冲突;ConflictPath 非空表示另存了冲突副本,为空表示已自动合并或保留了本地修改。
	EventConflict EventKind = "conflict"
	// EventError:单个文件或后台任务出错;Path 可能为空。
	EventError EventKind = "error"
)

// Direction 是同步方向。
type Direction string

const (
	// DirectionUp:本地 → 云端。
	DirectionUp Direction = "up"
	// DirectionDown:云端 → 本地。
	DirectionDown Direction = "down"
)

// Event 是引擎事件。路径一律是库内相对路径('/' 分隔、NFC)。
type Event struct {
	Kind         EventKind
	Path         string
	ConflictPath string
	Direction    Direction
	Bytes        int64
	Total        int64
	Reason       string
	Err          error
}

// New 校验参数、创建状态目录并打开状态库。
func New(opts Options) (*Engine, error) {
	switch {
	case opts.Keys == nil:
		return nil, errors.New("engine: 缺少 Keys")
	case opts.Client == nil:
		return nil, errors.New("engine: 缺少 Client")
	case opts.Trash == nil:
		return nil, errors.New("engine: 缺少 Trash 钩子(引擎不直接删除用户文件)")
	case strings.TrimSpace(opts.DeviceName) == "":
		return nil, errors.New("engine: 缺少 DeviceName(用于冲突副本命名)")
	case !uuid.Valid(opts.VaultID):
		return nil, fmt.Errorf("engine: VaultID %q 不是小写 UUID", opts.VaultID)
	case !filepath.IsAbs(opts.Root):
		return nil, fmt.Errorf("engine: Root %q 必须是绝对路径", opts.Root)
	case !filepath.IsAbs(opts.StateDir):
		return nil, fmt.Errorf("engine: StateDir %q 必须是绝对路径", opts.StateDir)
	}
	root := filepath.Clean(opts.Root)
	fi, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("engine: 库根目录: %w", err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("engine: 库根目录 %q 不是目录", root)
	}
	stateDir := filepath.Clean(opts.StateDir)
	if rel, err := filepath.Rel(root, stateDir); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		// 状态目录在库内:必须落在被内置规则忽略的 .typoza/ 下,否则状态库本身会被当成用户文件同步。
		first := strings.SplitN(filepath.ToSlash(rel), "/", 2)[0]
		if first != stateDirName {
			return nil, fmt.Errorf("engine: 状态目录在库内时必须位于 %s 下,当前为 %q", stateDirName, stateDir)
		}
	}
	if err := os.MkdirAll(filepath.Join(stateDir, baseDirName), 0o700); err != nil {
		return nil, fmt.Errorf("engine: 创建状态目录: %w", err)
	}
	st, err := openStore(filepath.Join(stateDir, "state.db"))
	if err != nil {
		return nil, err
	}
	return &Engine{
		root:       root,
		stateDir:   stateDir,
		vaultID:    opts.VaultID,
		deviceName: opts.DeviceName,
		keys:       opts.Keys,
		client:     opts.Client,
		trashFn:    opts.Trash,
		onEvent:    opts.OnEvent,
		store:      st,
		now:        time.Now,
		trigger:    make(chan struct{}, 1),
	}, nil
}

// Close 停止后台任务、等待进行中的同步结束并关闭状态库。重复调用无副作用。
func (e *Engine) Close() error {
	e.runMu.Lock()
	if e.closed {
		e.runMu.Unlock()
		return nil
	}
	e.closed = true
	if e.cancel != nil {
		e.cancel()
	}
	e.runMu.Unlock()
	e.wg.Wait()
	e.syncMu.Lock()
	defer e.syncMu.Unlock()
	return e.store.close()
}

// Status 返回状态快照。
func (e *Engine) Status() Status {
	e.statusMu.Lock()
	defer e.statusMu.Unlock()
	return e.status
}

// Root 返回本地库根目录。
func (e *Engine) Root() string { return e.root }

func (e *Engine) emit(ev Event) {
	if e.onEvent == nil {
		return
	}
	e.emitMu.Lock()
	defer e.emitMu.Unlock()
	e.onEvent(ev)
}

func (e *Engine) emitErr(path string, err error) {
	e.emit(Event{Kind: EventError, Path: path, Err: err})
}

// abs 把已校验的库内相对路径转成本机路径。
func (e *Engine) abs(rel string) string {
	return filepath.Join(e.root, filepath.FromSlash(rel))
}

func mergeable(rel string, size int64) bool {
	return size <= mergeMaxSize && mergeableExts[strings.ToLower(filepath.Ext(rel))]
}

// isFatal 判断错误是否应中止本轮同步(而不是只跳过当前文件):
// 取消、未登录/令牌失效、无权限、限流、服务器 5xx、网络错误、配额用尽。
func isFatal(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, api.ErrNotLoggedIn) {
		return true
	}
	var ae *api.Error
	if errors.As(err, &ae) {
		return ae.Status == 401 || ae.Status == 403 || ae.Status == 429 || ae.Status >= 500 ||
			ae.Code == api.CodeQuotaExceeded
	}
	var ue *url.Error
	return errors.As(err, &ue)
}
