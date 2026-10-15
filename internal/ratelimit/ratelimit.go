// Package ratelimit 是进程内存里的令牌桶限流器(同步协议 §6)。
//
// 计数只在单实例内生效:多实例部署时上限按实例计算,这是协议文档化的已知边界。
// 空闲且已回满的桶会被惰性清理,避免按 IP / 邮箱建桶导致内存无限增长。
package ratelimit

import (
	"sync"
	"time"
)

// sweepEvery 是惰性清理的最小间隔。
const sweepEvery = time.Minute

// Limiter 按任意字符串键限流。零值不可用,用 New 创建。
type Limiter struct {
	mu        sync.Mutex
	rate      float64 // 每秒补充的令牌数
	burst     float64 // 桶容量
	buckets   map[string]*bucket
	now       func() time.Time
	lastSweep time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// New 创建「每分钟 perMinute 次、可瞬时用满」的限流器;perMinute ≤ 0 表示不限流。
func New(perMinute int) *Limiter {
	return newWithClock(perMinute, time.Now)
}

func newWithClock(perMinute int, now func() time.Time) *Limiter {
	return &Limiter{
		rate:      float64(perMinute) / 60,
		burst:     float64(perMinute),
		buckets:   make(map[string]*bucket),
		now:       now,
		lastSweep: now(),
	}
}

// Allow 消耗 key 的一个令牌。不允许时返回需要等待的时长(用于 Retry-After)。
func (l *Limiter) Allow(key string) (bool, time.Duration) {
	if l.burst <= 0 {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	if now.Sub(l.lastSweep) >= sweepEvery {
		l.sweep(now)
	}
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	l.refill(b, now)
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := time.Duration((1 - b.tokens) / l.rate * float64(time.Second))
	if wait < time.Second {
		wait = time.Second
	}
	return false, wait
}

func (l *Limiter) refill(b *bucket, now time.Time) {
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens = min(l.burst, b.tokens+elapsed*l.rate)
		b.last = now
	}
}

// sweep 删除已经回满的桶:回满即等价于「从没来过」,删掉不影响限流语义。
func (l *Limiter) sweep(now time.Time) {
	for k, b := range l.buckets {
		l.refill(b, now)
		if b.tokens >= l.burst {
			delete(l.buckets, k)
		}
	}
	l.lastSweep = now
}

// size 返回当前桶数量(测试用)。
func (l *Limiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
