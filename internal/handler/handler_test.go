package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"threat-service/internal/domain"
	"threat-service/internal/service"
	"threat-service/internal/storage/memory"
)

const testMD5 = "d41d8cd98f00b204e9800998ecf8427e"

// newMux собирает хендлер поверх переданного хранилища.
func newMux(repo service.Repository) http.Handler {
	mux := http.NewServeMux()
	New(service.New(repo), slog.New(slog.NewTextHandler(io.Discard, nil))).Register(mux)
	return mux
}

// do выполняет запрос и возвращает код и тело ответа, разобранное в map.
func do(t *testing.T, h http.Handler, method, path, body string) (int, map[string]any, http.Header) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var out map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("ответ не JSON: %v (%q)", err, rec.Body.String())
		}
	}
	return rec.Code, out, rec.Header()
}

func TestCreate(t *testing.T) {
	h := newMux(memory.New())

	code, body, hdr := do(t, h, "POST", "/info", `{
		"md5": "`+strings.ToUpper(testMD5)+`",
		"name": "Trojan.Win32.Generic",
		"type": "trojan",
		"severity": "high",
		"file_size": 48213,
		"description": "тест"
	}`)

	if code != http.StatusCreated {
		t.Fatalf("код %d, тело %v", code, body)
	}
	if body["md5"] != testMD5 || body["name"] != "Trojan.Win32.Generic" || body["severity"] != "high" {
		t.Errorf("неожиданное тело: %v", body)
	}
	if body["file_size"] != float64(48213) {
		t.Errorf("file_size: %v", body["file_size"])
	}
	if body["created_at"] == nil || body["updated_at"] == nil {
		t.Errorf("нет служебных дат: %v", body)
	}
	if hdr.Get("Location") != "/info/"+testMD5 {
		t.Errorf("Location: %q", hdr.Get("Location"))
	}
}

func TestCreateOmitsEmptyOptionalFields(t *testing.T) {
	h := newMux(memory.New())

	_, body, _ := do(t, h, "POST", "/info", `{"md5":"`+testMD5+`","name":"A"}`)
	for _, key := range []string{"sha256", "type", "severity", "file_size", "description"} {
		if _, present := body[key]; present {
			t.Errorf("поле %q не задано, но есть в ответе", key)
		}
	}
}

func TestCreateErrors(t *testing.T) {
	h := newMux(memory.New())
	do(t, h, "POST", "/info", `{"md5":"`+testMD5+`","name":"A"}`)

	tests := []struct {
		name     string
		body     string
		wantCode int
		wantMsg  string
	}{
		{"дубликат", `{"md5":"` + testMD5 + `","name":"B"}`, http.StatusConflict, "Threat already exists"},
		{"плохой md5", `{"md5":"123","name":"B"}`, http.StatusBadRequest, "Validation failed"},
		{"нет имени", `{"md5":"11111111111111111111111111111111"}`, http.StatusBadRequest, "Validation failed"},
		{"плохой enum", `{"md5":"11111111111111111111111111111111","name":"B","severity":"huge"}`, http.StatusBadRequest, "Validation failed"},
		{"битый JSON", `{"md5":`, http.StatusBadRequest, "Invalid request body"},
		{"пустое тело", ``, http.StatusBadRequest, "Invalid request body"},
		{"неверный тип поля", `{"md5":"11111111111111111111111111111111","name":"B","file_size":"много"}`, http.StatusBadRequest, "Invalid request body"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, body, _ := do(t, h, "POST", "/info", tc.body)
			if code != tc.wantCode || body["message"] != tc.wantMsg {
				t.Errorf("код %d, тело %v; ожидали %d / %q", code, body, tc.wantCode, tc.wantMsg)
			}
		})
	}
}

func TestGet(t *testing.T) {
	h := newMux(memory.New())
	do(t, h, "POST", "/info", `{"md5":"`+testMD5+`","name":"Trojan"}`)

	code, body, _ := do(t, h, "GET", "/info/"+testMD5, "")
	if code != http.StatusOK || body["name"] != "Trojan" {
		t.Errorf("код %d, тело %v", code, body)
	}

	code, body, _ = do(t, h, "GET", "/info/ffffffffffffffffffffffffffffffff", "")
	if code != http.StatusNotFound || body["message"] != "Threat not found" {
		t.Errorf("не найдена: код %d, тело %v", code, body)
	}
	if !strings.Contains(body["details"].(string), "ffffffffffffffffffffffffffffffff") {
		t.Errorf("в details нет MD5: %v", body)
	}

	code, body, _ = do(t, h, "GET", "/info/not-an-md5", "")
	if code != http.StatusBadRequest || body["message"] != "Validation failed" {
		t.Errorf("плохой md5: код %d, тело %v", code, body)
	}
}

func TestUpdate(t *testing.T) {
	h := newMux(memory.New())
	do(t, h, "POST", "/info", `{"md5":"`+testMD5+`","name":"Old","severity":"low"}`)

	code, body, _ := do(t, h, "PUT", "/info/"+testMD5, `{"name":"New","type":"worm"}`)
	if code != http.StatusOK || body["name"] != "New" || body["type"] != "worm" {
		t.Fatalf("код %d, тело %v", code, body)
	}
	if _, present := body["severity"]; present {
		t.Errorf("PUT должен очищать не переданные поля: %v", body)
	}

	// Изменения действительно сохранились.
	_, body, _ = do(t, h, "GET", "/info/"+testMD5, "")
	if body["name"] != "New" {
		t.Errorf("после PUT GET вернул %v", body)
	}
}

func TestUpdateErrors(t *testing.T) {
	h := newMux(memory.New())

	code, _, _ := do(t, h, "PUT", "/info/"+testMD5, `{"name":"X"}`)
	if code != http.StatusNotFound {
		t.Errorf("несуществующая запись: код %d", code)
	}
	code, _, _ = do(t, h, "PUT", "/info/bad", `{"name":"X"}`)
	if code != http.StatusBadRequest {
		t.Errorf("плохой md5: код %d", code)
	}
	code, _, _ = do(t, h, "PUT", "/info/"+testMD5, `{}`)
	if code != http.StatusBadRequest {
		t.Errorf("нет имени: код %d", code)
	}
}

// Неожиданная ошибка хранилища — это 500 без утечки внутренностей наружу.
func TestInternalError(t *testing.T) {
	h := newMux(brokenRepo{})

	code, body, _ := do(t, h, "GET", "/info/"+testMD5, "")
	if code != http.StatusInternalServerError || body["message"] != "Internal server error" {
		t.Fatalf("код %d, тело %v", code, body)
	}
	if _, leaked := body["details"]; leaked {
		t.Errorf("детали внутренней ошибки не должны уходить клиенту: %v", body)
	}
}

type brokenRepo struct{}

var errBoom = errors.New("connection refused: secret-db-host:5432")

func (brokenRepo) Create(context.Context, domain.Threat) error { return errBoom }
func (brokenRepo) Get(context.Context, string) (domain.Threat, error) {
	return domain.Threat{}, errBoom
}
func (brokenRepo) Update(context.Context, domain.Threat) (domain.Threat, error) {
	return domain.Threat{}, errBoom
}
