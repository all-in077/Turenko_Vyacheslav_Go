// Package server собирает все части в один http.Handler:
// маршруты, и вокруг них цепочку middleware.
// Им пользуются и main, и интеграционные тесты, поэтому в тестах работает
// ровно то же самое, что и в бою.
package server

import (
	"log/slog"
	"net/http"

	"threat-service/internal/handler"
	"threat-service/internal/httpjson"
	"threat-service/internal/middleware"
	"threat-service/internal/service"
)

// maxBodyBytes — максимальный размер тела запроса. Записи об угрозах маленькие,
// мегабайта с запасом хватает.
const maxBodyBytes = 1 << 20

// Options — настройки защиты. Нулевые значения означают «выключено».
type Options struct {
	Logger         *slog.Logger
	APIKey         string  // пусто — авторизация выключена
	RateLimitRPS   float64 // 0 — rate-limit выключен
	RateLimitBurst int
}

// New собирает обработчик всего сервиса.
func New(svc *service.Service, opt Options) http.Handler {
	log := opt.Logger
	if log == nil {
		log = slog.Default()
	}

	// Основное API: /info и /info/{md5}.
	api := http.NewServeMux()
	handler.New(svc, log).Register(api)
	api.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		httpjson.Error(w, http.StatusNotFound, "Not found", "No such route: "+r.URL.Path)
	})

	// Защита применяется только к API. Порядок важен: чем раньше в списке,
	// тем «снаружи» обёртка. Сначала лимит запросов, потом ключ — так перебор
	// ключей тоже упирается в лимит.
	var protected http.Handler = api
	protected = middleware.BodyLimit(maxBodyBytes)(protected)
	if opt.APIKey != "" {
		protected = middleware.APIKey(opt.APIKey)(protected)
	}
	if opt.RateLimitRPS > 0 {
		protected = middleware.NewRateLimiter(opt.RateLimitRPS, opt.RateLimitBurst).Middleware()(protected)
	}

	// /healthz открыт без ключа и лимитов: его дёргают Docker и мониторинг.
	root := http.NewServeMux()
	root.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		httpjson.Write(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	root.Handle("/", protected)

	// Самый внешний слой — защита от паник, затем логирование всего, что прошло.
	var h http.Handler = root
	h = middleware.Logging(log)(h)
	h = middleware.Recover(log)(h)
	return h
}
