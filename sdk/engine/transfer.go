package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/ComeHereToSee/typoza-backend/sdk/crypto"
)

// parallel 以最多 limit 个并发执行 fn(0..n-1);任一失败即取消其余任务并返回第一个错误。
func parallel(ctx context.Context, limit, n int, fn func(ctx context.Context, i int) error) error {
	if n == 0 {
		return nil
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		first error
	)
	next := make(chan int)
	for w := 0; w < min(limit, n); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				if err := fn(ctx, i); err != nil {
					mu.Lock()
					if first == nil {
						first = err
						cancel()
					}
					mu.Unlock()
				}
			}
		}()
	}
feed:
	for i := 0; i < n; i++ {
		select {
		case next <- i:
		case <-ctx.Done():
			break feed
		}
	}
	close(next)
	wg.Wait()
	if first != nil {
		return first
	}
	return ctx.Err()
}

// uploaded 是一次上传的结果。
type uploaded struct {
	st     fileStat // 读取时的文件属性
	hash   string
	chunks []string
	data   []byte // 可合并文本(≤ 2 MiB)的全文,用于保存合并基线;否则为 nil
}

// upload 切块 → chunks/check → 并发上传缺失块(协议 §7.3)。
// 读取期间文件被改动时返回 errLocalChanged,本次放弃,下一轮重新上传。
func (e *Engine) upload(ctx context.Context, rel string) (*uploaded, error) {
	abs := e.abs(rel)
	f, err := os.Open(abs) // #nosec G304 -- 同步文件夹里的文件,rel 已校验不越出根目录
	if err != nil {
		return nil, fmt.Errorf("engine: 打开 %s: %w", rel, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("engine: 读取 %s 的属性: %w", rel, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("engine: %s 不是普通文件", rel)
	}
	st := statOf(fi)

	// 第一遍:切 4 MiB 块,算 chunkId 与全文摘要。只保留小文本的全文,大文件不常驻内存。
	h := crypto.NewContentHasher(e.keys.ChunkID)
	var ids []string
	var keep []byte
	keepAll := mergeable(rel, st.size)
	buf := make([]byte, crypto.ChunkSize)
	var total int64
	for {
		n, err := io.ReadFull(f, buf)
		if n > 0 {
			chunk := buf[:n]
			ids = append(ids, crypto.ChunkID(e.keys.ChunkID, chunk))
			_, _ = h.Write(chunk)
			if keepAll {
				keep = append(keep, chunk...)
			}
			total += int64(n)
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("engine: 读取 %s: %w", rel, err)
		}
	}
	if total != st.size {
		return nil, errLocalChanged
	}
	if keepAll && keep == nil {
		keep = []byte{}
	}
	up := &uploaded{st: st, hash: h.Sum(), chunks: ids, data: keep}

	if len(ids) > 0 {
		missing, err := e.client.CheckChunks(ctx, uniqueIDs(ids))
		if err != nil {
			return nil, fmt.Errorf("engine: 检查 %s 的块: %w", rel, err)
		}
		if err := e.uploadChunks(ctx, f, rel, ids, missing, total); err != nil {
			return nil, err
		}
	}
	if cur, err := statFile(abs); err != nil || !cur.exists || cur.size != st.size || cur.mtime != st.mtime {
		return nil, errLocalChanged
	}
	return up, nil
}

func uniqueIDs(ids []string) []string {
	seen := make(map[string]bool, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// uploadChunks 并发上传 missing 中的块;每块从文件按位置重读,并复核 chunkId 防止读到被改过的内容。
func (e *Engine) uploadChunks(ctx context.Context, f *os.File, rel string, ids, missing []string, total int64) error {
	if len(missing) == 0 {
		return nil
	}
	want := make(map[string]bool, len(missing))
	for _, id := range missing {
		want[id] = true
	}
	var jobs []int // 每个缺失块第一次出现的块序号
	for i, id := range ids {
		if want[id] {
			jobs = append(jobs, i)
			delete(want, id)
		}
	}
	if len(want) > 0 {
		return fmt.Errorf("engine: 服务器报告缺失的块不属于 %s", rel)
	}
	var sent atomic.Int64
	return parallel(ctx, transferConcurrency, len(jobs), func(ctx context.Context, j int) error {
		i := jobs[j]
		off := int64(i) * crypto.ChunkSize
		if off >= total {
			return errLocalChanged // 文件在两次读取之间被截短了
		}
		buf := make([]byte, min(int64(crypto.ChunkSize), total-off))
		n, err := f.ReadAt(buf, off)
		if n != len(buf) {
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
			return fmt.Errorf("engine: 重读 %s 的第 %d 块: %w", rel, i, err)
		}
		if crypto.ChunkID(e.keys.ChunkID, buf) != ids[i] {
			return errLocalChanged
		}
		sealed, err := crypto.EncryptChunk(e.keys.Chunk, ids[i], buf)
		if err != nil {
			return err
		}
		if err := e.client.PutChunk(ctx, ids[i], sealed); err != nil {
			return fmt.Errorf("engine: 上传 %s 的第 %d 块: %w", rel, i, err)
		}
		e.emit(Event{Kind: EventProgress, Path: rel, Direction: DirectionUp, Bytes: sent.Add(int64(len(buf))), Total: total})
		return nil
	})
}

// uploadMissing 在提交返回 missing_chunks 时补传(服务器的块可能在检查后被回收)。
// size 是生成 chunks 时的文件大小;文件已经变了就放弃,下一轮重新上传。
func (e *Engine) uploadMissing(ctx context.Context, rel string, chunks, missing []string, size int64) error {
	f, err := os.Open(e.abs(rel)) // #nosec G304 -- 同步文件夹里的文件,rel 已校验不越出根目录
	if err != nil {
		return fmt.Errorf("engine: 打开 %s: %w", rel, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("engine: 读取 %s 的属性: %w", rel, err)
	}
	if fi.Size() != size {
		return errLocalChanged
	}
	return e.uploadChunks(ctx, f, rel, chunks, missing, size)
}

// fetch 把清单 m 描述的内容下载到 rel 所在目录的临时文件:并发下载、解密、校验每块,
// 组装后核对全文摘要(协议 §2.3、§7.4)。返回临时文件路径;可合并文本同时返回全文。
func (e *Engine) fetch(ctx context.Context, rel string, m crypto.Manifest) (string, []byte, error) {
	if err := e.ensureParent(rel); err != nil {
		return "", nil, err
	}
	f, err := os.CreateTemp(filepath.Dir(e.abs(rel)), tmpPattern)
	if err != nil {
		return "", nil, fmt.Errorf("engine: 创建临时文件: %w", err)
	}
	tmp := f.Name()
	closed, ok := false, false
	defer func() {
		if !closed {
			_ = f.Close()
		}
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Truncate(m.Size); err != nil {
		return "", nil, fmt.Errorf("engine: 预分配 %s: %w", rel, err)
	}

	var got atomic.Int64
	err = e.downloadChunks(ctx, rel, m, func(off int64, plain []byte) error {
		if _, err := f.WriteAt(plain, off); err != nil {
			return fmt.Errorf("engine: 写临时文件: %w", err)
		}
		e.emit(Event{Kind: EventProgress, Path: rel, Direction: DirectionDown, Bytes: got.Add(int64(len(plain))), Total: m.Size})
		return nil
	})
	if err != nil {
		return "", nil, err
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", nil, fmt.Errorf("engine: 回读临时文件: %w", err)
	}
	h := crypto.NewContentHasher(e.keys.ChunkID)
	var w io.Writer = h
	var buf bytes.Buffer
	keep := mergeable(rel, m.Size)
	if keep {
		w = io.MultiWriter(h, &buf)
	}
	if _, err := io.Copy(w, f); err != nil {
		return "", nil, fmt.Errorf("engine: 回读临时文件: %w", err)
	}
	if h.Sum() != m.ContentHash {
		return "", nil, fmt.Errorf("engine: %s 下载后的内容摘要与清单不符(数据被篡改)", rel)
	}
	if err := f.Sync(); err != nil {
		return "", nil, fmt.Errorf("engine: 刷盘临时文件: %w", err)
	}
	closed = true
	if err := f.Close(); err != nil {
		return "", nil, fmt.Errorf("engine: 关闭临时文件: %w", err)
	}
	if !m.MTime.IsZero() {
		if err := os.Chtimes(tmp, m.MTime, m.MTime); err != nil {
			return "", nil, fmt.Errorf("engine: 设置 %s 的修改时间: %w", rel, err)
		}
	}
	var data []byte
	if keep {
		data = buf.Bytes()
		if data == nil {
			data = []byte{}
		}
	}
	ok = true
	return tmp, data, nil
}

// downloadChunks 并发下载清单 m 的全部块,逐块解密、HMAC 复核、核对长度后交给 put(偏移, 明文)。
// 同一块可能在文件里出现多次:只下载一次,对每个位置各调一次 put(put 须可并发调用)。
// 全文摘要由调用方在拼装后核对。
func (e *Engine) downloadChunks(ctx context.Context, rel string, m crypto.Manifest, put func(off int64, plain []byte) error) error {
	pos := make(map[string][]int, len(m.Chunks))
	var order []string
	for i, id := range m.Chunks {
		if _, ok := pos[id]; !ok {
			order = append(order, id)
		}
		pos[id] = append(pos[id], i)
	}
	return parallel(ctx, transferConcurrency, len(order), func(ctx context.Context, j int) error {
		id := order[j]
		sealed, err := e.client.GetChunk(ctx, id)
		if err != nil {
			return fmt.Errorf("engine: 下载 %s 的块 %s: %w", rel, id, err)
		}
		plain, err := crypto.DecryptChunk(e.keys.Chunk, e.keys.ChunkID, id, sealed)
		if err != nil {
			return fmt.Errorf("engine: %s: %w", rel, err)
		}
		for _, i := range pos[id] {
			off := int64(i) * crypto.ChunkSize
			if want := min(int64(crypto.ChunkSize), m.Size-off); int64(len(plain)) != want {
				return fmt.Errorf("engine: %s 的第 %d 块长度 %d,应为 %d", rel, i, len(plain), want)
			}
			if err := put(off, plain); err != nil {
				return err
			}
		}
		return nil
	})
}

// download 下载并原子落盘到 rel。目标状态不符合 ex(用户刚改过)时放弃,placed=false 且不报错。
func (e *Engine) download(ctx context.Context, rel string, m crypto.Manifest, ex expect) (st fileStat, data []byte, placed bool, err error) {
	tmp, data, err := e.fetch(ctx, rel, m)
	if err != nil {
		return fileStat{}, nil, false, err
	}
	st, err = e.place(tmp, rel, ex)
	if errors.Is(err, errLocalChanged) {
		return fileStat{}, nil, false, nil
	}
	if err != nil {
		return fileStat{}, nil, false, err
	}
	return st, data, true, nil
}
