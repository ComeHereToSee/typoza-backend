// Package migrations 内嵌数据库迁移 SQL,文件名格式 NNNN_说明.sql,按序号升序执行、每个只执行一次。
//
// 已发布的迁移文件不得修改,改表结构一律追加新文件。
package migrations

import "embed"

// FS 是全部迁移文件。
//
//go:embed *.sql
var FS embed.FS
