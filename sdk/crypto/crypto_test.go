package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
}

// RFC 5869 附录 A.1 Test Case 1(Basic test case with SHA-256)。
func TestHKDF_RFC5869Case1(t *testing.T) {
	ikm := mustHex(t, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt := mustHex(t, "000102030405060708090a0b0c")
	info := mustHex(t, "f0f1f2f3f4f5f6f7f8f9")
	want := mustHex(t, "3cb25f25faacd57a90434f64d0362f2a"+
		"2d2d0a90cf1a5a4c5db02d56ecc4c5bf"+
		"34007208d5b887185865")
	got, err := hkdfSHA256(ikm, salt, string(info), 42)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("OKM = %x, want %x", got, want)
	}
}

// RFC 4231 §4.3 Test Case 2(key = "Jefe")。
// HMAC 会把短于分组长度(64 字节)的密钥用 0 补齐,所以 "Jefe" 后补 28 个 0 字节的
// 32 字节 ChunkIDKey 与 RFC 的 4 字节密钥等价,可以直接验证 ChunkID 的实现。
func TestChunkID_RFC4231Case2(t *testing.T) {
	var k ChunkIDKey
	copy(k[:], "Jefe")
	data := []byte("what do ya want for nothing?")
	want := "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
	if got := ChunkID(k, data); got != want {
		t.Fatalf("ChunkID = %s, want %s", got, want)
	}
}

// Argon2id 已知答案测试。
// RFC 9106 §5.3 的向量带 secret(K)与 associated data(X),而 golang.org/x/crypto/argon2
// 的公开 API IDKey 不接受这两个参数,无法复现;这里改用 Argon2 参考实现
// (github.com/P-H-C/phc-winner-argon2 src/test.c,版本 0x13)的 Argon2id 向量,
// 与 RFC 9106 是同一算法、同一版本号。
func TestArgon2id_ReferenceVectors(t *testing.T) {
	cases := []struct {
		t, mKiB uint32
		p       uint8
		pwd     string
		salt    string
		want    string
	}{
		// hashtest(version, 2, 8, 2, "password", "somesalt", ...)
		{2, 256, 2, "password", "somesalt", "6d093c501fd5999645e0ea3bf620d7b8be7fd2db59c20d9fff9539da2bf57037"},
		// hashtest(version, 2, 8, 1, "password", "somesalt", ...)
		{2, 256, 1, "password", "somesalt", "9dfeb910e80bad0311fee20f9c0e2b12c17987b4cac90c2ef54d5b3021c68bfe"},
		// hashtest(version, 2, 16, 1, "password", "somesalt", ...)
		{2, 65536, 1, "password", "somesalt", "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7"},
	}
	for _, c := range cases {
		got := argon2id([]byte(c.pwd), []byte(c.salt), c.t, c.mKiB, c.p)
		if hex.EncodeToString(got) != c.want {
			t.Errorf("argon2id(t=%d,m=%d,p=%d) = %x, want %s", c.t, c.mKiB, c.p, got, c.want)
		}
	}
}

func lowKDF(salt []byte) KDFParams {
	return KDFParams{MemoryKiB: MinMemoryKiB, Iterations: MinIterations, Parallelism: 1, Salt: salt}
}

func TestDeriveMasterKey_NFCAndValidation(t *testing.T) {
	salt := bytes.Repeat([]byte{7}, SaltSize)
	composed := "caf\u00e9"    // é 预组合
	decomposed := "cafe\u0301" // e + 组合重音
	a, err := DeriveMasterKey(composed, lowKDF(salt))
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveMasterKey(decomposed, lowKDF(salt))
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("NFC 规范化后同一密码应派生出相同 MasterKey")
	}
	c, err := DeriveMasterKey("cafe", lowKDF(salt))
	if err != nil {
		t.Fatal(err)
	}
	if a == c {
		t.Fatal("不同密码不应派生出相同 MasterKey")
	}

	bad := []KDFParams{
		{MemoryKiB: MinMemoryKiB - 1, Iterations: 3, Parallelism: 1, Salt: salt},
		{MemoryKiB: MinMemoryKiB, Iterations: 1, Parallelism: 1, Salt: salt},
		{MemoryKiB: MinMemoryKiB, Iterations: 2, Parallelism: 0, Salt: salt},
		{MemoryKiB: MinMemoryKiB, Iterations: 2, Parallelism: 17, Salt: salt},
		{MemoryKiB: MinMemoryKiB, Iterations: 2, Parallelism: 1, Salt: salt[:8]},
		{MemoryKiB: 1<<20 + 1, Iterations: 2, Parallelism: 1, Salt: salt},
	}
	for i, p := range bad {
		if _, err := DeriveMasterKey("x", p); !errors.Is(err, ErrWeakKDF) {
			t.Errorf("case %d: err = %v, want ErrWeakKDF", i, err)
		}
	}
	if err := DefaultKDF().Validate(); err != nil {
		t.Fatalf("默认参数应合法: %v", err)
	}
}

func TestKeySeparation(t *testing.T) {
	var m MasterKey
	_, _ = rand.Read(m[:])
	if [KeySize]byte(m.AuthKey()) == [KeySize]byte(m.WrapKey()) {
		t.Fatal("authKey 与 wrapKey 必须不同")
	}
	ks := DeriveKeys(NewAccountKey())
	if [KeySize]byte(ks.Meta) == [KeySize]byte(ks.Chunk) || [KeySize]byte(ks.Chunk) == [KeySize]byte(ks.ChunkID) {
		t.Fatal("数据子密钥必须互不相同")
	}
	r := NewRecoveryKey()
	if [KeySize]byte(r.WrapKey()) == [KeySize]byte(r.AuthKey()) {
		t.Fatal("恢复包装密钥与恢复认证密钥必须不同")
	}
}

func TestSealOpen_RoundTripAndTamper(t *testing.T) {
	key := make([]byte, KeySize)
	_, _ = rand.Read(key)
	aad := []byte("typoza/v1/test")
	pt := []byte("hello 世界")
	sealed, err := seal(key, pt, aad)
	if err != nil {
		t.Fatal(err)
	}
	if sealed[0] != 0x01 || len(sealed) != len(pt)+SealOverhead {
		t.Fatalf("封装格式不对: 首字节 %x 长度 %d", sealed[0], len(sealed))
	}
	got, err := open(key, sealed, aad)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("往返失败: %q %v", got, err)
	}
	// 改任意 1 字节都必须报错。
	for i := range sealed {
		bad := bytes.Clone(sealed)
		bad[i] ^= 0x01
		if _, err := open(key, bad, aad); err == nil {
			t.Fatalf("改第 %d 字节后仍能解开", i)
		}
	}
	// 版本号未知必须报格式错误而不是尝试解密。
	bad := bytes.Clone(sealed)
	bad[0] = 0x02
	if _, err := open(key, bad, aad); !errors.Is(err, ErrFormat) {
		t.Fatalf("未知版本号 err = %v, want ErrFormat", err)
	}
	if _, err := open(key, sealed, []byte("typoza/v1/other")); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("错 AAD err = %v, want ErrDecrypt", err)
	}
	other := make([]byte, KeySize)
	if _, err := open(other, sealed, aad); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("错密钥 err = %v, want ErrDecrypt", err)
	}
	if _, err := open(key, sealed[:SealOverhead-1], aad); !errors.Is(err, ErrFormat) {
		t.Fatalf("过短 err = %v, want ErrFormat", err)
	}
	// 两次封装同一明文 nonce 不同。
	s2, _ := seal(key, pt, aad)
	if bytes.Equal(sealed, s2) {
		t.Fatal("两次封装结果相同,nonce 没有随机化")
	}
}

func TestAccountKeyWrap(t *testing.T) {
	var m MasterKey
	_, _ = rand.Read(m[:])
	ak := NewAccountKey()
	sealed, err := WrapAccountKey(m.WrapKey(), ak)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnwrapAccountKey(m.WrapKey(), sealed)
	if err != nil || got != ak {
		t.Fatalf("往返失败: %v", err)
	}
	var m2 MasterKey
	_, _ = rand.Read(m2[:])
	if _, err := UnwrapAccountKey(m2.WrapKey(), sealed); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("错主密码 err = %v", err)
	}
	r := NewRecoveryKey()
	rs, err := WrapAccountKeyForRecovery(r.WrapKey(), ak)
	if err != nil {
		t.Fatal(err)
	}
	got, err = UnwrapAccountKeyForRecovery(r.WrapKey(), rs)
	if err != nil || got != ak {
		t.Fatalf("恢复包装往返失败: %v", err)
	}
}

const (
	testVault = "0b7d7d6e-8f3a-4c1e-9a43-1f2e3d4c5b6a"
	testFile  = "5a4b3c2d-1e0f-4a9b-8c7d-6e5f4a3b2c1d"
	testFile2 = "6a4b3c2d-1e0f-4a9b-8c7d-6e5f4a3b2c1d"
)

func TestVaultName(t *testing.T) {
	ks := DeriveKeys(NewAccountKey())
	sealed, err := EncryptVaultName(ks.Meta, testVault, "我的笔记")
	if err != nil {
		t.Fatal(err)
	}
	name, err := DecryptVaultName(ks.Meta, testVault, sealed)
	if err != nil || name != "我的笔记" {
		t.Fatalf("往返失败: %q %v", name, err)
	}
	if _, err := DecryptVaultName(ks.Meta, "1b7d7d6e-8f3a-4c1e-9a43-1f2e3d4c5b6a", sealed); err == nil {
		t.Fatal("换了 vaultId 仍能解开库名")
	}
	if _, err := EncryptVaultName(ks.Meta, "NOT-A-UUID", "x"); err == nil {
		t.Fatal("非法 vaultId 应报错")
	}
}

func TestManifest_RoundTripAndBinding(t *testing.T) {
	ks := DeriveKeys(NewAccountKey())
	content := []byte("# 周报\n")
	m := Manifest{
		Path:        "笔记/周报.md",
		Size:        int64(len(content)),
		MTime:       time.Date(2026, 10, 16, 1, 2, 3, 123456789, time.UTC),
		ContentHash: ContentHash(ks.ChunkID, content),
		Chunks:      []string{ChunkID(ks.ChunkID, content)},
	}
	sealed, err := EncryptManifest(ks.Meta, testVault, testFile, 3, m)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptManifest(ks.Meta, testVault, testFile, 3, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if got.Path != m.Path || got.Size != m.Size || got.ContentHash != m.ContentHash ||
		len(got.Chunks) != 1 || got.Chunks[0] != m.Chunks[0] || got.Deleted {
		t.Fatalf("往返不一致: %+v", got)
	}
	// mtime 截断到毫秒、UTC。
	if want := time.Date(2026, 10, 16, 1, 2, 3, 123000000, time.UTC); !got.MTime.Equal(want) {
		t.Fatalf("mtime = %v, want %v", got.MTime, want)
	}
	if _, err := DecryptManifest(ks.Meta, testVault, testFile, 4, sealed); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("错版本号 err = %v, want ErrDecrypt", err)
	}
	if _, err := DecryptManifest(ks.Meta, testVault, testFile2, 3, sealed); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("错 fileId err = %v, want ErrDecrypt", err)
	}
	bad := bytes.Clone(sealed)
	bad[len(bad)/2] ^= 0x80
	if _, err := DecryptManifest(ks.Meta, testVault, testFile, 3, bad); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("篡改 err = %v, want ErrDecrypt", err)
	}
	if _, err := EncryptManifest(ks.Meta, testVault, testFile, 0, m); err == nil {
		t.Fatal("版本号 0 应报错")
	}
}

func TestManifest_Validate(t *testing.T) {
	ks := DeriveKeys(NewAccountKey())
	tomb := Manifest{Path: "a.md", MTime: time.Now(), Deleted: true}
	sealed, err := EncryptManifest(ks.Meta, testVault, testFile, 2, tomb)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptManifest(ks.Meta, testVault, testFile, 2, sealed)
	if err != nil || !got.Deleted || len(got.Chunks) != 0 {
		t.Fatalf("墓碑往返失败: %v", err)
	}
	invalid := []Manifest{
		{Path: "../a.md", ContentHash: ContentHash(ks.ChunkID, nil)},
		{Path: "/a.md", ContentHash: ContentHash(ks.ChunkID, nil)},
		{Path: "a//b.md", ContentHash: ContentHash(ks.ChunkID, nil)},
		{Path: "a.md", Deleted: true, Size: 1},
		{Path: "a.md", Size: 1, ContentHash: ContentHash(ks.ChunkID, nil)},                                                        // 缺块
		{Path: "a.md", Size: 0, ContentHash: "XYZ"},                                                                               // 摘要格式
		{Path: "a.md", Size: ChunkSize + 1, ContentHash: ContentHash(ks.ChunkID, nil), Chunks: []string{strings.Repeat("a", 64)}}, // 块数不够
	}
	for i, m := range invalid {
		if _, err := EncryptManifest(ks.Meta, testVault, testFile, 1, m); err == nil {
			t.Errorf("case %d 应校验失败: %+v", i, m)
		}
	}
	// 空文件:0 块。
	empty := Manifest{Path: "empty.txt", ContentHash: ContentHash(ks.ChunkID, nil), MTime: time.Now()}
	if _, err := EncryptManifest(ks.Meta, testVault, testFile, 1, empty); err != nil {
		t.Fatalf("空文件清单应合法: %v", err)
	}
}

func TestChunk_RoundTripCompressionAndTamper(t *testing.T) {
	ks := DeriveKeys(NewAccountKey())
	compressible := bytes.Repeat([]byte("typoza "), 10000)
	random := make([]byte, 64*1024)
	_, _ = rand.Read(random)
	for name, plain := range map[string][]byte{"compressible": compressible, "random": random} {
		id := ChunkID(ks.ChunkID, plain)
		sealed, err := EncryptChunk(ks.Chunk, id, plain)
		if err != nil {
			t.Fatal(err)
		}
		// 检查 flags:可压缩的置位且密文明显变小;随机数据不压缩。
		pt, err := open(chunkKey(ks.Chunk, id), sealed, []byte(aadChunkPrefix+id))
		if err != nil {
			t.Fatal(err)
		}
		switch name {
		case "compressible":
			if pt[0] != flagDeflate || len(sealed) >= len(plain) {
				t.Fatalf("可压缩块应置压缩位: flags=%x sealed=%d plain=%d", pt[0], len(sealed), len(plain))
			}
		case "random":
			if pt[0] != 0 || !bytes.Equal(pt[1:], plain) {
				t.Fatalf("随机块不应压缩: flags=%x", pt[0])
			}
		}
		got, err := DecryptChunk(ks.Chunk, ks.ChunkID, id, sealed)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("%s 往返失败: %v", name, err)
		}
		bad := bytes.Clone(sealed)
		bad[len(bad)-1] ^= 0x01
		if _, err := DecryptChunk(ks.Chunk, ks.ChunkID, id, bad); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("%s 篡改 err = %v", name, err)
		}
	}

	// 服务器把块 B 的密文当作块 A 返回:AAD/密钥都绑定 chunkId,解密失败。
	a, b := []byte("chunk A"), []byte("chunk B")
	idA, idB := ChunkID(ks.ChunkID, a), ChunkID(ks.ChunkID, b)
	sealedB, _ := EncryptChunk(ks.Chunk, idB, b)
	if _, err := DecryptChunk(ks.Chunk, ks.ChunkID, idA, sealedB); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("调换块 err = %v, want ErrDecrypt", err)
	}
	// 密文能解开但明文与 chunkId 不符(持有密钥的一方伪造):HMAC 复核必须拦住。
	forged, err := seal(chunkKey(ks.Chunk, idA), append([]byte{0}, b...), []byte(aadChunkPrefix+idA))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptChunk(ks.Chunk, ks.ChunkID, idA, forged); !errors.Is(err, ErrChunkMismatch) {
		t.Fatalf("内容不符 err = %v, want ErrChunkMismatch", err)
	}
	// 未知 flags 位必须报错。
	weird, _ := seal(chunkKey(ks.Chunk, idA), append([]byte{0x02}, a...), []byte(aadChunkPrefix+idA))
	if _, err := DecryptChunk(ks.Chunk, ks.ChunkID, idA, weird); !errors.Is(err, ErrFormat) {
		t.Fatalf("未知 flags err = %v, want ErrFormat", err)
	}
	if _, err := EncryptChunk(ks.Chunk, "ABC", a); err == nil {
		t.Fatal("非法 chunkId 应报错")
	}
}

func TestContentHash(t *testing.T) {
	ks := DeriveKeys(NewAccountKey())
	data := []byte("abcdef")
	h := NewContentHasher(ks.ChunkID)
	_, _ = h.Write(data[:2])
	_, _ = h.Write(data[2:])
	if h.Sum() != ContentHash(ks.ChunkID, data) {
		t.Fatal("流式与一次性摘要不一致")
	}
	// 内容摘要带 "typoza/v1/file|" 前缀,与同内容的 chunkId 必须不同。
	if ContentHash(ks.ChunkID, data) == ChunkID(ks.ChunkID, data) {
		t.Fatal("contentHash 与 chunkId 不应相同")
	}
	if !ValidContentHash(ContentHash(ks.ChunkID, nil)) {
		t.Fatal("摘要应为 64 位小写十六进制")
	}
}

func TestRecoveryCode(t *testing.T) {
	k := NewRecoveryKey()
	code := FormatRecoveryCode(k)
	groups := strings.Split(code, "-")
	if len(groups) != 13 {
		t.Fatalf("应为 13 组,实际 %d: %s", len(groups), code)
	}
	for _, g := range groups {
		if len(g) != 4 || strings.Trim(g, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") != "" {
			t.Fatalf("分组格式错误: %q", g)
		}
	}
	for _, in := range []string{
		code,
		strings.ToLower(code),
		strings.ReplaceAll(code, "-", ""),
		" " + strings.ReplaceAll(code, "-", " \n") + " ",
	} {
		got, err := ParseRecoveryCode(in)
		if err != nil || got != k {
			t.Fatalf("解析 %q 失败: %v", in, err)
		}
	}
	if _, err := ParseRecoveryCode(code[:len(code)-5]); err == nil {
		t.Fatal("截短的恢复码应报错")
	}
	if _, err := ParseRecoveryCode(strings.Replace(code, code[:1], "1", 1)); err == nil {
		t.Fatal("含字母表外字符(1)应报错")
	}
	// RFC 4648 §10 Base32 测试向量,确认字母表与无填充编码。
	if got := recoveryEncoding.EncodeToString([]byte("foobar")); got != "MZXW6YTBOI" {
		t.Fatalf("base32(foobar) = %s", got)
	}
}
