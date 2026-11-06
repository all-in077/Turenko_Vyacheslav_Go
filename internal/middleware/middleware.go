// Package middleware — «обёртки» вокруг HTTP-обработчиков: защита от падений,
// логирование, ограничение размера тела, проверка API-ключа и rate-limit.
//
// Все они имеют одну и ту же форму func(http.Handler) http.Handler,
// поэтому их можно свободно комбинировать (см. internal/server).
package middleware

import (
	"crypto/sha256"
	"crypto/subtle"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"threat-service/internal/httpjson"
)

// Recover ловит панику в обработчике, пишет её в лог и отвечает 500,
// чтобы один кривой запрос не клал весь сервер.
func Recover(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				rec := recover()
				if rec == nil {
					return
				}
				if rec == http.ErrAbortHandler {
					panic(rec) // это штатный способ оборвать ответ, не глотаем его
				}
				log.Error("паника в обработчике", "panic", rec, "stack", string(debug.Stack()))
				httpjson.Error(w, http.StatusInternalServerError, "Internal server error", "")
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// Logging пишет по строчке на каждый запрос: метод, путь, код ответа, время.
func Logging(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)
			log.Info("запрос",
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.status,
				"duration", time.Since(start).Round(time.Microsecond),
				"remote", clientIP(r),
			)
		})
	}
}

// statusRecorder запоминает код ответа, чтобы его можно было залогировать.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// BodyLimit не даёт прислать тело запроса больше maxBytes: дальше читать его нельзя,
// и хендлер получит ошибку чтения. Защищает от попыток забить память огромным JSON.
func BodyLimit(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			next.ServeHTTP(w, r)
		})
	}
}

// APIKey пропускает только запросы с правильным заголовком X-API-Key.
func APIKey(key string) func(http.Handler) http.Handler {
	// Сравниваем хеши: так время проверки не зависит ни от длины ключа,
	// ни от того, на каком символе он перестал совпадать.
	want := sha256.Sum256([]byte(key))

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got := sha256.Sum256([]byte(r.Header.Get("X-API-Key")))
			if subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
				httpjson.Error(w, http.StatusUnauthorized, "Unauthorized", "Missing or invalid X-API-Key header")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
