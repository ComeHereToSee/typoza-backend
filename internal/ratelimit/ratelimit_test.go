package ratelimit

import (
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func TestBurstThenDeny(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	l := newWithClock(30, clk.now)
	for i := range 30 {
		if ok, _ := l.Allow("ip:1"); !ok {
			t.Fatalf("第 %d 次应放行", i+1)
		}
	}
	ok, wait := l.Allow("ip:1")
	if ok {
		t.Fatalf("第 31 次应拒绝")
	}
	if wait < time.Second || wait > 3*time.Second {
		t.Fatalf("30 次/分钟时补一个令牌约需 2 秒,实际等待 %v", wait)
	}
	// 其它键互不影响。
	if ok, _ := l.Allow("ip:2"); !ok {
		t.Fatalf("不同键应各自计数")
	}
}

func TestRefill(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	l := newWithClock(60, clk.now) // 每秒补 1 个
	for range 60 {
		l.Allow("k")
	}
	if ok, _ := l.Allow("k"); ok {
		t.Fatalf("用满后应拒绝")
	}
	clk.advance(time.Second)
	if ok, _ := l.Allow("k"); !ok {
		t.Fatalf("过 1 秒应补回 1 个令牌")
	}
	if ok, _ := l.Allow("k"); ok {
		t.Fatalf("只补了 1 个令牌")
	}
	clk.advance(10 * time.Minute)
	for i := range 60 {
		if ok, _ := l.Allow("k"); !ok {
			t.Fatalf("长时间空闲后应回满,第 %d 次被拒", i+1)
		}
	}
}

func TestSweepRemovesIdleBuckets(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	l := newWithClock(10, clk.now)
	for i := range 100 {
		l.Allow(string(rune('a'+i%26)) + string(rune('a'+i/26)))
	}
	if l.size() != 100 {
		t.Fatalf("应有 100 个桶,实际 %d", l.size())
	}
	clk.advance(2 * time.Minute)
	l.Allow("new")
	if l.size() != 1 {
		t.Fatalf("回满的空闲桶应被清理,剩 %d 个", l.size())
	}
}

func TestDisabled(t *testing.T) {
	l := New(0)
	for range 10000 {
		if ok, _ := l.Allow("k"); !ok {
			t.Fatalf("perMinute=0 表示不限流")
		}
	}
}

func TestConcurrentAllow(t *testing.T) {
	l := New(100)
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	for range 20 {
		wg.Go(func() {
			for range 10 {
				if ok, _ := l.Allow("shared"); ok {
					mu.Lock()
					allowed++
					mu.Unlock()
				}
			}
		})
	}
	wg.Wait()
	if allowed < 100 || allowed > 102 {
		t.Fatalf("200 次并发请求应约放行 100 次,实际 %d", allowed)
	}
}
