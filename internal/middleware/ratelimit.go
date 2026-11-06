package middleware

import (
	"fmt"
	"math"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"threat-service/internal/httpjson"
)

// RateLimiter ограничивает частоту запросов с одного IP-адреса алгоритмом
// «ведро с токенами»: ведро вмещает burst токенов и пополняется со скоростью
// rps токенов в секунду, каждый запрос забирает один токен. Нет токенов — 429.
// Так клиент может ненадолго превысить среднюю скорость (burst), но не сидеть на ней вечно.
//
// Важно: адрес берётся из соединения (RemoteAddr). Если сервис стоит за
// reverse-proxy, все запросы будут выглядеть как идущие с адреса прокси —
// тогда лимит надо считать по X-Forwarded-For, но доверять ему можно только от своего прокси.
type RateLimiter struct {
	mu        sync.Mutex
	rps       float64
	burst     float64
	buckets   map[string]*bucket
	lastSweep time.Time
	now       func() time.Time // подменяется в тестах
}

type bucket struct {
	tokens float64
	last   time.Time
}

// NewRateLimiter создаёт лимитер: rps запросов в секунду, всплеск до burst.
func NewRateLimiter(rps float64, burst int) *RateLimiter {
	if burst < 1 {
		burst = 1
	}
	return &RateLimiter{
		rps:     rps,
		burst:   float64(burst),
		buckets: make(map[string]*bucket),
		now:     time.Now,
	}
}

// Middleware возвращает обёртку, которая отвечает 429, когда лимит исчерпан.
func (l *RateLimiter) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ok, retryAfter := l.allow(clientIP(r))
			if !ok {
				secs := int(math.Ceil(retryAfter.Seconds()))
				w.Header().Set("Retry-After", strconv.Itoa(secs))
				httpjson.Error(w, http.StatusTooManyRequests, "Too many requests",
					fmt.Sprintf("Rate limit exceeded, retry after %d s", secs))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// allow решает, пускать ли запрос; если нет — через сколько можно повторить.
func (l *RateLimiter) allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	l.sweep(now)

	b, found := l.buckets[key]
	if !found {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}

	// Пополняем ведро за время, прошедшее с прошлого запроса.
	b.tokens = math.Min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rps)
	b.last = now

	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := time.Duration((1 - b.tokens) / l.rps * float64(time.Second))
	return false, wait
}

// sweep раз в минуту выбрасывает ведра тех, кто давно не приходил, чтобы map не рос вечно.
// Ведро, простоявшее дольше времени полного пополнения, и так было бы полным,
// поэтому удалять его безопасно: новое будет ничем не отличаться.
func (l *RateLimiter) sweep(now time.Time) {
	if now.Sub(l.lastSweep) < time.Minute {
		return
	}
	l.lastSweep = now

	idle := time.Duration(l.burst / l.rps * float64(time.Second))
	if idle < time.Minute {
		idle = time.Minute
	}
	for key, b := range l.buckets {
		if now.Sub(b.last) > idle {
			delete(l.buckets, key)
		}
	}
}

// clientIP возвращает IP клиента без порта.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
