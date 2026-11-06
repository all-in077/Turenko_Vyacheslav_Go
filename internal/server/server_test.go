package server

// Интеграционные тесты: поднимаем настоящий HTTP-сервер (httptest.Server)
// с полной цепочкой middleware и ходим в него обычным http-клиентом,
// как это делал бы внешний потребитель API.

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"threat-service/internal/service"
	"threat-service/internal/storage/memory"
)

const testMD5 = "d41d8cd98f00b204e9800998ecf8427e"

func newServer(t *testing.T, opt Options) *httptest.Server {
	t.Helper()
	opt.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httptest.NewServer(New(service.New(memory.New()), opt))
	t.Cleanup(srv.Close)
	return srv
}

func call(t *testing.T, srv *httptest.Server, method, path, body, apiKey string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("ответ не JSON: %q", raw)
		}
	}
	return resp.StatusCode, out
}

// Полный жизненный цикл записи: создали → прочитали → дубликат → обновили → прочитали.
func TestLifecycle(t *testing.T) {
	srv := newServer(t, Options{})

	code, body := call(t, srv, "POST", "/info", `{"md5":"`+testMD5+`","name":"Trojan.Win32.Generic","severity":"medium"}`, "")
	if code != http.StatusCreated || body["md5"] != testMD5 {
		t.Fatalf("создание: %d %v", code, body)
	}

	code, body = call(t, srv, "GET", "/info/"+testMD5, "", "")
	if code != http.StatusOK || body["name"] != "Trojan.Win32.Generic" {
		t.Fatalf("чтение: %d %v", code, body)
	}

	code, body = call(t, srv, "POST", "/info", `{"md5":"`+testMD5+`","name":"Other"}`, "")
	if code != http.StatusConflict {
		t.Fatalf("дубликат: %d %v", code, body)
	}

	code, body = call(t, srv, "PUT", "/info/"+testMD5, `{"name":"Trojan.Win32.Updated","severity":"critical"}`, "")
	if code != http.StatusOK || body["name"] != "Trojan.Win32.Updated" || body["severity"] != "critical" {
		t.Fatalf("обновление: %d %v", code, body)
	}

	code, body = call(t, srv, "GET", "/info/"+testMD5, "", "")
	if code != http.StatusOK || body["name"] != "Trojan.Win32.Updated" {
		t.Fatalf("чтение после обновления: %d %v", code, body)
	}
}

func TestErrorsAreJSON(t *testing.T) {
	srv := newServer(t, Options{})

	tests := []struct {
		name, method, path, body string
		want                     int
	}{
		{"нет такой записи", "GET", "/info/ffffffffffffffffffffffffffffffff", "", http.StatusNotFound},
		{"плохой md5", "GET", "/info/xyz", "", http.StatusBadRequest},
		{"PUT несуществующей", "PUT", "/info/" + testMD5, `{"name":"A"}`, http.StatusNotFound},
		{"битый JSON", "POST", "/info", `{`, http.StatusBadRequest},
		{"неизвестный маршрут", "GET", "/nope", "", http.StatusNotFound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, body := call(t, srv, tc.method, tc.path, tc.body, "")
			if code != tc.want {
				t.Fatalf("код %d, ожидали %d (%v)", code, tc.want, body)
			}
			if body["message"] == nil {
				t.Errorf("в ответе нет поля message: %v", body)
			}
		})
	}
}

func TestBodyTooLarge(t *testing.T) {
	srv := newServer(t, Options{})
	huge := `{"md5":"` + testMD5 + `","name":"A","description":"` + strings.Repeat("x", maxBodyBytes) + `"}`

	code, _ := call(t, srv, "POST", "/info", huge, "")
	if code != http.StatusBadRequest {
		t.Errorf("огромное тело: код %d", code)
	}
}

func TestAPIKey(t *testing.T) {
	srv := newServer(t, Options{APIKey: "secret"})

	if code, _ := call(t, srv, "GET", "/info/"+testMD5, "", ""); code != http.StatusUnauthorized {
		t.Errorf("без ключа: код %d", code)
	}
	if code, _ := call(t, srv, "GET", "/info/"+testMD5, "", "wrong"); code != http.StatusUnauthorized {
		t.Errorf("с неверным ключом: код %d", code)
	}
	// С верным ключом доходим до хендлера: записи нет, значит 404, а не 401.
	if code, _ := call(t, srv, "GET", "/info/"+testMD5, "", "secret"); code != http.StatusNotFound {
		t.Errorf("с верным ключом: код %d", code)
	}
	// Healthz открыт без ключа.
	if code, body := call(t, srv, "GET", "/healthz", "", ""); code != http.StatusOK || body["status"] != "ok" {
		t.Errorf("healthz: %d %v", code, body)
	}
}

func TestRateLimit(t *testing.T) {
	srv := newServer(t, Options{RateLimitRPS: 0.001, RateLimitBurst: 2})

	for i := 1; i <= 2; i++ {
		if code, _ := call(t, srv, "GET", "/info/"+testMD5, "", ""); code != http.StatusNotFound {
			t.Fatalf("запрос %d: код %d", i, code)
		}
	}
	code, body := call(t, srv, "GET", "/info/"+testMD5, "", "")
	if code != http.StatusTooManyRequests || body["message"] == nil {
		t.Errorf("третий запрос: %d %v", code, body)
	}
	// Healthz лимитом не ограничивается.
	if code, _ := call(t, srv, "GET", "/healthz", "", ""); code != http.StatusOK {
		t.Errorf("healthz при исчерпанном лимите: код %d", code)
	}
}
