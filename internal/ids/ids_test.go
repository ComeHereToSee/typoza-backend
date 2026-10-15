package ids

import "testing"

func TestNewIsValidAndUnique(t *testing.T) {
	seen := map[string]bool{}
	for range 1000 {
		id := New()
		if !Valid(id) {
			t.Fatalf("New() 生成了非规范 UUID: %q", id)
		}
		if id[14] != '4' {
			t.Fatalf("版本位应为 4: %q", id)
		}
		if c := id[19]; c != '8' && c != '9' && c != 'a' && c != 'b' {
			t.Fatalf("变体位不符合 RFC 9562: %q", id)
		}
		if seen[id] {
			t.Fatalf("重复 UUID: %q", id)
		}
		seen[id] = true
	}
}

func TestValid(t *testing.T) {
	cases := map[string]bool{
		"3f2b8c4e-1d2a-4b6c-9e8f-0a1b2c3d4e5f": true,
		"3F2B8C4E-1D2A-4B6C-9E8F-0A1B2C3D4E5F": false, // 大写不接受
		"3f2b8c4e1d2a4b6c9e8f0a1b2c3d4e5f":     false,
		"3f2b8c4e-1d2a-4b6c-9e8f-0a1b2c3d4e5":  false,
		"3f2b8c4e-1d2a-4b6c-9e8f_0a1b2c3d4e5f": false,
		"":                                     false,
	}
	for in, want := range cases {
		if got := Valid(in); got != want {
			t.Errorf("Valid(%q) = %v, 期望 %v", in, got, want)
		}
	}
}
