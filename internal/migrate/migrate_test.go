package migrate

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/ComeHereToSee/typoza-backend/migrations"
)

func TestLoadSortsAndValidates(t *testing.T) {
	fsys := fstest.MapFS{
		"0002_b.sql": {Data: []byte("SELECT 2")},
		"0001_a.sql": {Data: []byte("SELECT 1")},
		"README.md":  {Data: []byte("忽略")},
	}
	migs, err := load(fsys)
	if err != nil {
		t.Fatal(err)
	}
	if len(migs) != 2 || migs[0].version != 1 || migs[1].version != 2 {
		t.Fatalf("应按序号排序: %+v", migs)
	}
	for _, bad := range []fstest.MapFS{
		{"abc_x.sql": {Data: []byte("x")}},
		{"0001.sql": {Data: []byte("x")}},
		{"0001_a.sql": {Data: []byte("x")}, "0001_b.sql": {Data: []byte("y")}},
	} {
		if _, err := load(bad); err == nil {
			t.Fatalf("应拒绝非法迁移集: %v", bad)
		}
	}
}

func TestEmbeddedMigrationsLoad(t *testing.T) {
	migs, err := load(migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	if len(migs) == 0 || migs[0].version != 1 || !strings.Contains(migs[0].sql, "CREATE TABLE users") {
		t.Fatalf("内嵌迁移应从 0001 开始并建 users 表")
	}
}
