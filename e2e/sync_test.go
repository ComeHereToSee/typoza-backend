package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ComeHereToSee/typoza-backend/sdk/account"
	"github.com/ComeHereToSee/typoza-backend/sdk/api"
	"github.com/ComeHereToSee/typoza-backend/sdk/crypto"
)

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// TestE2E_RegisterTwoDevicesSync:注册 + 两台设备登录,A 写 B 收,B 改 A 收。
func TestE2E_RegisterTwoDevicesSync(t *testing.T) {
	e := newEnv(t)
	u, a, code := e.register("设备A")
	if len(strings.Split(code, "-")) != 13 {
		t.Fatalf("恢复码格式不对: %s", code)
	}
	b := u.login("设备B", u.password)
	if a.sess.Keys.Account != b.sess.Keys.Account {
		t.Fatal("两台设备解出的账户密钥不同")
	}

	dir := e.secret("目录名")
	name := e.secret("文件名") + ".md"
	body := "# 周报\n" + e.secret("正文") + "\n"
	a.writeStr(dir+"/"+name, body)
	a.writeStr("空文件.txt", "")
	a.write("附件/"+e.secret("附件名")+".bin", append(randBytes(3000), []byte(e.secret("二进制内容"))...))
	a.sync()
	b.sync()
	assertSameFiles(t, a, b)

	edited := body + e.secret("B 的追加") + "\n"
	b.writeStr(dir+"/"+name, edited)
	b.sync()
	a.sync()
	if a.read(dir+"/"+name) != edited {
		t.Fatal("A 未收到 B 的修改")
	}
	assertSameFiles(t, a, b)
}

const base7 = "第1行\n第2行\n第3行\n第4行\n第5行\n第6行\n第7行\n"

// TestE2E_ConcurrentEdits:同时改同一文本——不重叠自动合并、重叠出冲突副本;二进制冲突出冲突副本。
func TestE2E_ConcurrentEdits(t *testing.T) {
	e := newEnv(t)
	u, a, _ := e.register("设备A")
	b := u.login("设备B", u.password)
	merged := e.secret("合并") + ".md"
	clash := e.secret("冲突") + ".md"
	bin := e.secret("图片") + ".png"
	a.writeStr(merged, base7)
	a.writeStr(clash, base7)
	a.write(bin, randBytes(4096))
	a.sync()
	b.sync()

	// 不重叠:A 改第 1 行,B 改第 7 行。
	a.writeStr(merged, strings.Replace(base7, "第1行", "第1行 A", 1))
	b.writeStr(merged, strings.Replace(base7, "第7行", "第7行 B", 1))
	// 重叠:双方改同一行。
	a.writeStr(clash, strings.Replace(base7, "第4行", "第4行 A", 1))
	b.writeStr(clash, strings.Replace(base7, "第4行", "第4行 B", 1))
	// 二进制:双方各写不同内容。
	binA, binB := randBytes(4096), randBytes(5000)
	a.write(bin, binA)
	b.write(bin, binB)

	a.sync()
	b.sync()
	a.sync()
	b.sync()
	assertSameFiles(t, a, b)
	files := a.files()

	wantMerged := strings.Replace(strings.Replace(base7, "第1行", "第1行 A", 1), "第7行", "第7行 B", 1)
	if files[merged] != wantMerged {
		t.Fatalf("不重叠修改应自动合并:\n%q", files[merged])
	}
	if files[clash] != strings.Replace(base7, "第4行", "第4行 A", 1) {
		t.Fatalf("重叠修改时原路径应是先提交的 A 版本:\n%q", files[clash])
	}
	if files[bin] != string(binA) {
		t.Fatal("二进制冲突时原路径应是先提交的 A 版本")
	}
	cs := conflictCopies(files)
	if len(cs) != 2 {
		t.Fatalf("应有 2 个冲突副本(文本重叠 + 二进制),实际 %v", cs)
	}
	var gotText, gotBin bool
	for _, c := range cs {
		if !strings.Contains(c, "设备B") {
			t.Errorf("冲突副本应带 B 的设备名: %s", c)
		}
		switch {
		case strings.HasSuffix(c, ".md"):
			gotText = files[c] == strings.Replace(base7, "第4行", "第4行 B", 1)
		case strings.HasSuffix(c, ".png"):
			gotBin = files[c] == string(binB)
		}
	}
	if !gotText || !gotBin {
		t.Fatalf("冲突副本必须保存 B 的内容: text=%v bin=%v %v", gotText, gotBin, cs)
	}
}

// TestE2E_DeleteTrashRestore:A 删除 → B 的 Trash 钩子被调用 → 从回收站恢复 → 两边都回来。
func TestE2E_DeleteTrashRestore(t *testing.T) {
	e := newEnv(t)
	u, a, _ := e.register("设备A")
	b := u.login("设备B", u.password)
	name := e.secret("将被删除") + ".md"
	content := e.secret("删除前内容") + "\n"
	a.writeStr(name, content)
	a.writeStr("保留.md", "keep\n")
	a.sync()
	b.sync()

	a.remove(name)
	a.sync()
	b.sync()
	if got := b.trashedPaths(); len(got) != 1 || got[0] != name {
		t.Fatalf("B 应通过 Trash 钩子移走 %s: %v", name, got)
	}
	if b.exists(name) {
		t.Fatal("B 的文件应已被移走")
	}

	items, err := b.eng.Trash(context.Background())
	if err != nil || len(items) != 1 || items[0].Path != name {
		t.Fatalf("回收站应列出被删文件: %+v %v", items, err)
	}
	if err := b.eng.RestoreFromTrash(context.Background(), items[0].FileID); err != nil {
		t.Fatal(err)
	}
	if b.read(name) != content {
		t.Fatal("B 恢复后内容不对")
	}
	a.sync()
	if a.read(name) != content {
		t.Fatal("A 应收到恢复的文件")
	}
	if items, err := a.eng.Trash(context.Background()); err != nil || len(items) != 0 {
		t.Fatalf("恢复后回收站应为空: %+v %v", items, err)
	}
}

// TestE2E_HistoryRestore:改三次 → 恢复到第 1 版 → 两台设备都是第 1 版。
func TestE2E_HistoryRestore(t *testing.T) {
	e := newEnv(t)
	u, a, _ := e.register("设备A")
	b := u.login("设备B", u.password)
	name := e.secret("历史") + ".md"
	var versions []string
	for i := 1; i <= 3; i++ {
		v := fmt.Sprintf("第 %d 版 %s\n", i, e.secret("版本内容"))
		versions = append(versions, v)
		a.writeStr(name, v)
		a.sync()
	}
	b.sync()
	vs, err := b.eng.Versions(context.Background(), name)
	if err != nil || len(vs) != 3 || vs[0].Version != 3 || vs[2].Version != 1 {
		t.Fatalf("历史版本不对: %+v %v", vs, err)
	}
	if err := b.eng.Restore(context.Background(), name, 1); err != nil {
		t.Fatal(err)
	}
	if b.read(name) != versions[0] {
		t.Fatal("B 恢复后应是第 1 版")
	}
	a.sync()
	if a.read(name) != versions[0] {
		t.Fatal("A 应收到恢复后的第 1 版")
	}
	vs, err = a.eng.Versions(context.Background(), name)
	if err != nil || len(vs) != 4 || vs[0].ContentHash != vs[3].ContentHash {
		t.Fatalf("恢复应产生内容等于第 1 版的新版本: %+v %v", vs, err)
	}
}

// TestE2E_ChangePassword:改主密码后旧密码登录失败、新密码可用、数据可解,其他设备被登出。
func TestE2E_ChangePassword(t *testing.T) {
	e := newEnv(t)
	u, a, _ := e.register("设备A")
	b := u.login("设备B", u.password)
	name := e.secret("改密前") + ".md"
	content := e.secret("改密前内容") + "\n"
	a.writeStr(name, content)
	a.sync()
	b.sync()

	newPassword := e.secret("新主密码")
	if err := account.ChangePassword(context.Background(), a.client, u.email, u.password, newPassword, a.sess.Keys); err != nil {
		t.Fatal(err)
	}
	if _, err := account.Login(context.Background(), e.newClient(nil), u.email, u.password, account.LoginOptions{
		Device: api.Device{Name: "旧密码", Platform: "macos"},
	}); !api.IsCode(err, api.CodeUnauthorized) {
		t.Fatalf("旧密码应登录失败: %v", err)
	}
	// 除当前设备外全部登出。
	if err := b.eng.SyncNow(context.Background()); !api.IsAuthError(err) {
		t.Fatalf("改密后其他设备应被登出: %v", err)
	}
	a.writeStr(name, content+"改密后 A 仍可同步\n")
	a.sync()

	c := u.login("设备C", newPassword)
	if c.sess.Keys.Account != a.sess.Keys.Account {
		t.Fatal("改密后账户密钥应不变")
	}
	c.sync()
	if c.read(name) != content+"改密后 A 仍可同步\n" {
		t.Fatal("新密码登录的设备应能解开数据")
	}
}

// TestE2E_RecoveryReset:用恢复码重置主密码,新密码可用、数据可解,旧密码失效。
func TestE2E_RecoveryReset(t *testing.T) {
	e := newEnv(t)
	u, a, code := e.register("设备A")
	name := e.secret("恢复前") + ".md"
	content := e.secret("恢复前内容") + "\n"
	a.writeStr(name, content)
	a.sync()

	newPassword := e.secret("恢复后主密码")
	r := e.blankDevice("设备R")
	sess, err := account.Recover(context.Background(), r.client, u.email, strings.ToLower(code), newPassword,
		api.Device{Name: "设备R", Platform: "macos"})
	if err != nil {
		t.Fatal(err)
	}
	if sess.Keys.Account != a.sess.Keys.Account {
		t.Fatal("恢复后账户密钥应不变")
	}
	if _, err := account.Login(context.Background(), e.newClient(nil), u.email, u.password, account.LoginOptions{
		Device: api.Device{Name: "旧密码", Platform: "macos"},
	}); !api.IsCode(err, api.CodeUnauthorized) {
		t.Fatalf("恢复后旧密码应失败: %v", err)
	}
	// 恢复会吊销所有设备令牌。
	if err := a.eng.SyncNow(context.Background()); !api.IsAuthError(err) {
		t.Fatalf("恢复后原设备应被登出: %v", err)
	}
	c := u.login("设备C", newPassword)
	c.sync()
	if c.read(name) != content {
		t.Fatal("恢复后新密码登录的设备应能解开数据")
	}
	// 错误的恢复码。
	wrong := crypto.FormatRecoveryCode(crypto.NewRecoveryKey())
	if _, err := account.Recover(context.Background(), e.newClient(nil), u.email, wrong, "x",
		api.Device{Name: "错误", Platform: "macos"}); !api.IsAuthError(err) {
		t.Fatalf("错误恢复码应失败: %v", err)
	}
}

// TestE2E_LargeFileAndDedup:大于 4 MiB 的多块文件;同内容两文件、文件内重复块都只上传一次;改名不重传。
func TestE2E_LargeFileAndDedup(t *testing.T) {
	e := newEnv(t)
	u, a, _ := e.register("设备A")
	b := u.login("设备B", u.password)
	big := append(randBytes(2*crypto.ChunkSize+777), []byte(e.secret("大文件尾部"))...) // 3 块
	a.write("大文件.bin", big)
	a.write("大文件副本.bin", big)
	a.write("全零.bin", make([]byte, 2*crypto.ChunkSize+5)) // 2 种块
	a.sync()
	if got := a.puts.Load(); got != 5 {
		t.Fatalf("块应去重后只上传 5 次,实际 %d", got)
	}
	b.sync()
	assertSameFiles(t, a, b)
	if !bytes.Equal([]byte(b.read("大文件.bin")), big) {
		t.Fatal("大文件内容不对")
	}

	// 改名:旧路径墓碑 + 新路径新文件,复用块不重传。
	before := a.puts.Load()
	if err := os.MkdirAll(filepath.Join(a.root, "归档"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(a.root, "大文件.bin"), filepath.Join(a.root, "归档", "大文件.bin")); err != nil {
		t.Fatal(err)
	}
	a.sync()
	if a.puts.Load() != before {
		t.Fatalf("改名不应重传块: %d → %d", before, a.puts.Load())
	}
	b.sync()
	if b.exists("大文件.bin") || !bytes.Equal([]byte(b.read("归档/大文件.bin")), big) {
		t.Fatal("B 应完成改名")
	}
	if got := b.trashedPaths(); len(got) != 1 || got[0] != "大文件.bin" {
		t.Fatalf("改名在 B 端表现为旧路径移入废纸篓: %v", got)
	}
}

// TestE2E_LiveSync:后台模式——A 本地写文件经去抖上传,B 收到服务器推送后立即拉取。
func TestE2E_LiveSync(t *testing.T) {
	e := newEnv(t)
	u, a, _ := e.register("设备A")
	b := u.login("设备B", u.password)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := a.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	name := e.secret("实时") + ".md"
	content := e.secret("实时内容") + "\n"
	time.Sleep(300 * time.Millisecond)
	if err := os.WriteFile(filepath.Join(a.root, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		if data, err := os.ReadFile(filepath.Join(b.root, name)); err == nil && string(data) == content {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("B 未在 20 秒内收到文件;A 状态 %+v,B 状态 %+v", a.eng.Status(), b.eng.Status())
		}
		time.Sleep(100 * time.Millisecond)
	}
	cancel()
	if err := a.eng.Close(); err != nil {
		t.Fatal(err)
	}
	if err := b.eng.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestE2E_TamperedServerData:存储里的块密文被篡改时,客户端必须拒绝落盘并报错。
func TestE2E_TamperedServerData(t *testing.T) {
	e := newEnv(t)
	u, a, _ := e.register("设备A")
	b := u.login("设备B", u.password)
	name := e.secret("被篡改") + ".md"
	a.writeStr(name, e.secret("篡改前内容")+"\n")
	a.sync()

	ctx := context.Background()
	bs, err := e.blobs()
	if err != nil {
		t.Fatal(err)
	}
	keys, err := bs.list(ctx)
	if err != nil || len(keys) != 1 {
		t.Fatalf("应只有 1 个块对象: %v %v", keys, err)
	}
	data, err := bs.get(ctx, keys[0])
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 0xff
	if err := bs.put(ctx, keys[0], data); err != nil {
		t.Fatal(err)
	}
	err = b.eng.SyncNow(ctx)
	if !errors.Is(err, crypto.ErrDecrypt) {
		t.Fatalf("篡改的块必须被拒绝: %v", err)
	}
	if b.exists(name) {
		t.Fatal("校验失败的内容不能落盘")
	}
}
