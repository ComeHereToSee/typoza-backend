package engine

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// fileRecord 是本地状态库中一个已同步文件的记录(协议 §7.1),键为库内相对路径。
type fileRecord struct {
	FileID  string `json:"fileId"`
	Version int64  `json:"version"`
	// MTime、Size 是记录时本地文件的 mtime(UnixNano)与大小:二者都没变就认为内容没变,不重读(协议 §7.2)。
	MTime int64 `json:"mtime"`
	Size  int64 `json:"size"`
	// ContentHash、Chunks 是该版本(上次同步)的内容摘要与块列表。
	ContentHash string   `json:"contentHash"`
	Chunks      []string `json:"chunks"`
	// NeedsCommit 表示本地有尚未提交的变化,即使摘要与记录相同也要提交
	// (合并结果待上传、冲突让位后路径变了、远端删除但本地有修改需复活)。
	NeedsCommit bool `json:"needsCommit,omitempty"`
}

var (
	bucketFiles = []byte("files") // 路径 → fileRecord JSON
	bucketIDs   = []byte("ids")   // fileId → 路径
	bucketMeta  = []byte("meta")
	keyCursor   = []byte("cursor")
)

// store 是基于 bbolt 的状态库,每库一个文件。bbolt 自身支持并发读写事务。
type store struct {
	db *bolt.DB
}

func openStore(path string) (*store, error) {
	// Timeout:同一个库被两个引擎实例同时打开时,第二个拿不到文件锁,1 秒后报错而不是永久阻塞。
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, fmt.Errorf("engine: 打开状态库 %s(是否已有同一库的引擎在运行?): %w", path, err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketFiles, bucketIDs, bucketMeta} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("engine: 初始化状态库: %w", err)
	}
	return &store{db: db}, nil
}

func (s *store) close() error {
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("engine: 关闭状态库: %w", err)
	}
	return nil
}

func decodeRecord(path string, data []byte) (*fileRecord, error) {
	var r fileRecord
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("engine: 状态库中 %q 的记录损坏: %w", path, err)
	}
	return &r, nil
}

// get 取路径的记录;不存在返回 nil。
func (s *store) get(path string) (*fileRecord, error) {
	var rec *fileRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketFiles).Get([]byte(path))
		if data == nil {
			return nil
		}
		var err error
		rec, err = decodeRecord(path, data)
		return err
	})
	return rec, err
}

// byID 按 fileId 取记录及其路径;不存在返回 ("", nil, nil)。
func (s *store) byID(fileID string) (string, *fileRecord, error) {
	var path string
	var rec *fileRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		p := tx.Bucket(bucketIDs).Get([]byte(fileID))
		if p == nil {
			return nil
		}
		path = string(p)
		data := tx.Bucket(bucketFiles).Get(p)
		if data == nil {
			return fmt.Errorf("engine: 状态库索引不一致:%s 指向不存在的路径 %q", fileID, path)
		}
		var err error
		rec, err = decodeRecord(path, data)
		return err
	})
	if err != nil {
		return "", nil, err
	}
	return path, rec, nil
}

// all 返回全部记录。
func (s *store) all() (map[string]*fileRecord, error) {
	out := make(map[string]*fileRecord)
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketFiles).ForEach(func(k, v []byte) error {
			rec, err := decodeRecord(string(k), v)
			if err != nil {
				return err
			}
			out[string(k)] = rec
			return nil
		})
	})
	return out, err
}

// put 写入路径的记录并维护 fileId 索引:同一 fileId 原来在别的路径时删掉旧路径键;
// 该路径原来属于别的 fileId 时删掉那个 fileId 的索引。
func (s *store) put(path string, rec *fileRecord) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("engine: 序列化 %q 的记录: %w", path, err)
	}
	err = s.db.Update(func(tx *bolt.Tx) error {
		files, ids := tx.Bucket(bucketFiles), tx.Bucket(bucketIDs)
		if old := ids.Get([]byte(rec.FileID)); old != nil && string(old) != path {
			oldPath := string(old) // bbolt 返回的切片在修改后失效,先复制
			if err := files.Delete([]byte(oldPath)); err != nil {
				return err
			}
		}
		if cur := files.Get([]byte(path)); cur != nil {
			prev, err := decodeRecord(path, cur)
			if err != nil {
				return err
			}
			if prev.FileID != rec.FileID {
				if err := ids.Delete([]byte(prev.FileID)); err != nil {
					return err
				}
			}
		}
		if err := files.Put([]byte(path), data); err != nil {
			return err
		}
		return ids.Put([]byte(rec.FileID), []byte(path))
	})
	if err != nil {
		return fmt.Errorf("engine: 写入 %q 的记录: %w", path, err)
	}
	return nil
}

// remove 删除路径的记录及其索引。
func (s *store) remove(path string) error {
	err := s.db.Update(func(tx *bolt.Tx) error {
		files, ids := tx.Bucket(bucketFiles), tx.Bucket(bucketIDs)
		cur := files.Get([]byte(path))
		if cur == nil {
			return nil
		}
		rec, err := decodeRecord(path, cur)
		if err != nil {
			return err
		}
		if p := ids.Get([]byte(rec.FileID)); p != nil && string(p) == path {
			if err := ids.Delete([]byte(rec.FileID)); err != nil {
				return err
			}
		}
		return files.Delete([]byte(path))
	})
	if err != nil {
		return fmt.Errorf("engine: 删除 %q 的记录: %w", path, err)
	}
	return nil
}

// cursor 返回 changes 游标(从未同步过为 0)。
func (s *store) cursor() (int64, error) {
	var c int64
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketMeta).Get(keyCursor)
		if v == nil {
			return nil
		}
		if len(v) != 8 {
			return fmt.Errorf("engine: 状态库游标损坏(%d 字节)", len(v))
		}
		c = int64(binary.BigEndian.Uint64(v)) // #nosec G115 -- 游标是本库自己写入的非负值
		return nil
	})
	return c, err
}

func (s *store) setCursor(c int64) error {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(c)) // #nosec G115 -- 游标来自服务端变更序号,非负
	err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketMeta).Put(keyCursor, b[:])
	})
	if err != nil {
		return fmt.Errorf("engine: 保存游标: %w", err)
	}
	return nil
}
