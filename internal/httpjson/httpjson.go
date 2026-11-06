// Package httpjson — пара мелких помощников для JSON-ответов.
// Нужны и хендлерам, и middleware, чтобы все ответы (включая ошибки) выглядели одинаково.
package httpjson

import (
	"encoding/json"
	"net/http"
)

// ErrorBody — формат ошибки из спецификации (схема ErrorResponse).
type ErrorBody struct {
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

// Write отправляет v как JSON с указанным статусом.
// Сначала сериализуем, потом пишем: если сериализация упадёт, клиент получит
// нормальную 500, а не наполовину записанный ответ.
func Write(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		status = http.StatusInternalServerError
		body = []byte(`{"message":"Internal server error"}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// Error отправляет ошибку в формате {"message": "...", "details": "..."}.
func Error(w http.ResponseWriter, status int, message, details string) {
	Write(w, status, ErrorBody{Message: message, Details: details})
}
