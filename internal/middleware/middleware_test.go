package middleware

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var ok = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestRecover(t *testing.T) {
	boom := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("ой") })
	h := Recover(discardLog())(boom)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("код %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "ой") {
		t.Errorf("текст паники утёк клиенту: %s", rec.Body.String())
	}
}

func TestAPIKey(t *testing.T) {
	h := APIKey("secret")(ok)

	tests := []struct {
		name   string
		header string
		want   int
	}{
		{"верный ключ", "secret", http.StatusOK},
		{"неверный ключ", "wrong", http.StatusUnauthorized},
		{"ключа нет", "", http.StatusUnauthorized},
		{"префикс ключа", "secre", http.StatusUnauthorized},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			if tc.header != "" {
				req.Header.Set("X-API-Key", tc.header)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Errorf("код %d, ожидали %d", rec.Code, tc.want)
			}
		})
	}
}

func TestBodyLimit(t *testing.T) {
	read := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	h := BodyLimit(10)(read)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/", strings.NewReader("short")))
	if rec.Code != http.StatusOK {
		t.Errorf("маленькое тело: код %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/", strings.NewReader(strings.Repeat("a", 11))))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("большое тело: код %d", rec.Code)
	}
}

func TestRateLimiter(t *testing.T) {
	l := NewRateLimiter(1, 2) // 1 запрос/сек, всплеск до 2
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return clock }

	// Первые два проходят (всплеск), третий — нет.
	for i := 0; i < 2; i++ {
		if allowed, _ := l.allow("1.1.1.1"); !allowed {
			t.Fatalf("запрос %d должен был пройти", i+1)
		}
	}
	allowed, wait := l.allow("1.1.1.1")
	if allowed || wait <= 0 || wait > time.Second {
		t.Fatalf("третий запрос: allowed=%v wait=%v", allowed, wait)
	}

	// Другой клиент не страдает из-за первого.
	if allowed, _ := l.allow("2.2.2.2"); !allowed {
		t.Error("лимит не должен быть общим для разных IP")
	}

	// Через секунду ведро пополнилось на один токен.
	clock = clock.Add(time.Second)
	if allowed, _ := l.allow("1.1.1.1"); !allowed {
		t.Error("после паузы запрос должен пройти")
	}
	if allowed, _ := l.allow("1.1.1.1"); allowed {
		t.Error("токен был один, второй запрос подряд должен быть отклонён")
	}
}

func TestRateLimiterMiddleware(t *testing.T) {
	l := NewRateLimiter(0.001, 1)
	h := l.Middleware()(ok)

	do := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "10.0.0.1:5555"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	if rec := do(); rec.Code != http.StatusOK {
		t.Fatalf("первый запрос: код %d", rec.Code)
	}
	rec := do()
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("второй запрос: код %d", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("нет заголовка Retry-After")
	}
}

func TestRateLimiterSweep(t *testing.T) {
	l := NewRateLimiter(10, 10)
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return clock }

	l.allow("1.1.1.1")
	clock = clock.Add(10 * time.Minute)
	l.allow("2.2.2.2") // этот вызов запускает уборку

	if _, exists := l.buckets["1.1.1.1"]; exists {
		t.Error("давно неактивное ведро должно быть удалено")
	}
	if _, exists := l.buckets["2.2.2.2"]; !exists {
		t.Error("свежее ведро удалять нельзя")
	}
}
