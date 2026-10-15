// Package store 是 PostgreSQL 仓储:手写参数化 SQL,需要原子性的操作在一个事务里完成。
//
// 这里只做数据访问与事务内必须一并完成的判断(如提交时的版本冲突、块齐全);
// 口令、令牌、配额策略等业务规则在 service 包。
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 仓储层的哨兵错误,service 层把它们映射成协议错误码。
var (
	ErrNotFound      = errors.New("记录不存在")
	ErrForbidden     = errors.New("无权访问该资源")
	ErrEmailTaken    = errors.New("邮箱已注册")
	ErrVaultExists   = errors.New("库 ID 已存在")
	ErrNotDeleted    = errors.New("文件不在回收站")
	ErrQuotaExceeded = errors.New("超出存储配额")
	ErrTokenInvalid  = errors.New("令牌不存在、已过期或已吊销")
	ErrRefreshReuse  = errors.New("刷新令牌被重放")
)

// ConflictError 表示提交时 baseVersion 不是当前版本。Head 为 nil 表示文件不存在(例如已被永久删除)。
type ConflictError struct {
	Head *Version
}

func (e *ConflictError) Error() string { return "版本冲突" }

// MissingChunksError 表示提交引用了未上传的块。
type MissingChunksError struct {
	IDs []string
}

func (e *MissingChunksError) Error() string { return fmt.Sprintf("缺少 %d 个块", len(e.IDs)) }

// Store 封装连接池。
type Store struct {
	pool *pgxpool.Pool
}

// New 用已建好的连接池创建仓储。
func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// Connect 创建连接池并确认数据库可达。
func Connect(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("解析数据库连接串: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("连接数据库: %w", err)
	}
	return pool, nil
}

// Pool 返回底层连接池(测试与运维工具用)。
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Ping 检查数据库可用(就绪探针)。
func (s *Store) Ping(ctx context.Context) error {
	if err := s.pool.Ping(ctx); err != nil {
		return fmt.Errorf("数据库不可用: %w", err)
	}
	return nil
}

// querier 是连接池与事务的公共方法集,同一段 SQL 可在两者上执行。
type querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// inTx 在事务中执行 fn;fn 返回错误则回滚。
func (s *Store) inTx(ctx context.Context, fn func(pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, s.pool, fn)
}

// isUniqueViolation 判断是否违反了指定唯一约束(SQLSTATE 23505)。
func isUniqueViolation(err error, constraint string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == constraint
}

// nullable 把空字符串转成 SQL NULL。
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// WithTryLock 尝试获取以 name 命名的会话级 advisory lock,拿到才执行 fn。
// 多实例部署时保证后台回收任务同一时刻只有一个实例在跑;锁键带 schema 名,并行测试互不干扰。
func (s *Store) WithTryLock(ctx context.Context, name string, fn func(context.Context) error) (acquired bool, err error) {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return false, fmt.Errorf("获取数据库连接: %w", err)
	}
	var ok bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtext(current_schema() || ':' || $1::text))`, name).Scan(&ok); err != nil {
		conn.Release()
		return false, fmt.Errorf("尝试获取锁 %s: %w", name, err)
	}
	if !ok {
		conn.Release()
		return false, nil
	}
	fnErr := fn(ctx)
	bg := context.WithoutCancel(ctx)
	if _, unlockErr := conn.Exec(bg, `SELECT pg_advisory_unlock(hashtext(current_schema() || ':' || $1::text))`, name); unlockErr != nil {
		// 解锁失败时关闭这条连接(会话结束锁自动释放),绝不能把仍持锁的连接还回池里。
		closeErr := conn.Hijack().Close(bg)
		return true, errors.Join(fnErr, fmt.Errorf("释放锁 %s: %w", name, unlockErr), closeErr)
	}
	conn.Release()
	return true, fnErr
}

// utc 统一把数据库返回的时间转成 UTC。
func utc(t time.Time) time.Time { return t.UTC() }
