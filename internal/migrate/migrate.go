// Package migrate 是极简数据库迁移器:schema_migrations 记录已执行版本,
// 会话级 advisory lock 保证多实例同时启动时只有一个在迁移、其余等待。
package migrate

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

// 锁键按 schema 区分:同一数据库里的不同 schema(例如并行测试)互不阻塞。
const (
	lockSQL   = `SELECT pg_advisory_lock(hashtext(current_schema() || ':typoza-migrate'))`
	unlockSQL = `SELECT pg_advisory_unlock(hashtext(current_schema() || ':typoza-migrate'))`
)

type migration struct {
	version int64
	name    string
	sql     string
}

// Up 执行 fsys 中尚未执行的迁移。用独立连接而不是连接池:
// 会话级锁绑定连接,用完直接关闭连接即可确保锁释放,不会把带锁的连接还回池里。
func Up(ctx context.Context, databaseURL string, fsys fs.FS, log *slog.Logger) (err error) {
	migs, err := load(fsys)
	if err != nil {
		return err
	}
	conn, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		return fmt.Errorf("迁移连接数据库: %w", err)
	}
	defer func() {
		if closeErr := conn.Close(context.WithoutCancel(ctx)); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("关闭迁移连接: %w", closeErr))
		}
	}()

	if _, err := conn.Exec(ctx, lockSQL); err != nil {
		return fmt.Errorf("获取迁移锁: %w", err)
	}
	defer func() {
		if _, unlockErr := conn.Exec(context.WithoutCancel(ctx), unlockSQL); unlockErr != nil {
			err = errors.Join(err, fmt.Errorf("释放迁移锁: %w", unlockErr))
		}
	}()

	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    bigint      PRIMARY KEY,
		name       text        NOT NULL,
		applied_at timestamptz NOT NULL DEFAULT now()
	)`); err != nil {
		return fmt.Errorf("创建 schema_migrations: %w", err)
	}

	applied, err := appliedVersions(ctx, conn)
	if err != nil {
		return err
	}
	for _, m := range migs {
		if applied[m.version] {
			continue
		}
		err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			// 无参数的 Exec 走简单查询协议,允许一个文件里有多条语句。
			if _, err := tx.Exec(ctx, m.sql); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version, name) VALUES ($1, $2)`, m.version, m.name)
			return err
		})
		if err != nil {
			return fmt.Errorf("执行迁移 %s: %w", m.name, err)
		}
		log.Info("数据库迁移完成", "migration", m.name)
	}
	return nil
}

func appliedVersions(ctx context.Context, conn *pgx.Conn) (map[int64]bool, error) {
	rows, err := conn.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("读取已执行迁移: %w", err)
	}
	defer rows.Close()
	applied := map[int64]bool{}
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("读取已执行迁移: %w", err)
		}
		applied[v] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("读取已执行迁移: %w", err)
	}
	return applied, nil
}

// load 读取并排序迁移文件,序号重复或文件名不合规直接报错。
func load(fsys fs.FS) ([]migration, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("列出迁移文件: %w", err)
	}
	var out []migration
	seen := map[int64]string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".sql") {
			continue
		}
		prefix, _, ok := strings.Cut(name, "_")
		if !ok {
			return nil, fmt.Errorf("迁移文件名应为 NNNN_说明.sql: %s", name)
		}
		v, err := strconv.ParseInt(prefix, 10, 64)
		if err != nil || v <= 0 {
			return nil, fmt.Errorf("迁移文件序号无效: %s", name)
		}
		if prev, dup := seen[v]; dup {
			return nil, fmt.Errorf("迁移序号重复: %s 与 %s", prev, name)
		}
		seen[v] = name
		body, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, fmt.Errorf("读取迁移 %s: %w", name, err)
		}
		out = append(out, migration{version: v, name: name, sql: string(body)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}
