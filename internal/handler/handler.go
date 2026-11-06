// Package handler — HTTP-слой: разбирает запросы, вызывает сервис и
// превращает результат (или ошибку) в ответ по спецификации.
package handler

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"threat-service/internal/domain"
	"threat-service/internal/httpjson"
	"threat-service/internal/service"
)

// Handler обрабатывает запросы /info.
type Handler struct {
	svc *service.Service
	log *slog.Logger
}

// New создаёт обработчик.
func New(svc *service.Service, log *slog.Logger) *Handler {
	return &Handler{svc: svc, log: log}
}

// Register вешает маршруты на mux. Шаблоны вида "GET /info/{md5}"
// поддерживаются стандартным роутером начиная с Go 1.22.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /info", h.create)
	mux.HandleFunc("GET /info/{md5}", h.get)
	mux.HandleFunc("PUT /info/{md5}", h.update)
}

// POST /info
func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	var req createRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	created, err := h.svc.Create(r.Context(), req.toDomain(req.MD5))
	if err != nil {
		h.fail(w, r, err, req.MD5)
		return
	}

	w.Header().Set("Location", "/info/"+created.MD5)
	httpjson.Write(w, http.StatusCreated, toResponse(created))
}

// GET /info/{md5}
func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	md5 := r.PathValue("md5")

	t, err := h.svc.Get(r.Context(), md5)
	if err != nil {
		h.fail(w, r, err, md5)
		return
	}
	httpjson.Write(w, http.StatusOK, toResponse(t))
}

// PUT /info/{md5}
func (h *Handler) update(w http.ResponseWriter, r *http.Request) {
	md5 := r.PathValue("md5")

	var req updateRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	t, err := h.svc.Update(r.Context(), md5, req.toDomain(md5))
	if err != nil {
		h.fail(w, r, err, md5)
		return
	}
	httpjson.Write(w, http.StatusOK, toResponse(t))
}

// decodeJSON читает тело запроса. При ошибке сам отвечает 400 и возвращает false.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	err := json.NewDecoder(r.Body).Decode(dst)
	if err == nil {
		return true
	}

	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		httpjson.Error(w, http.StatusBadRequest, "Invalid request body", "request body is too large")
	case errors.Is(err, io.EOF):
		httpjson.Error(w, http.StatusBadRequest, "Invalid request body", "request body is empty")
	default:
		httpjson.Error(w, http.StatusBadRequest, "Invalid request body", "body must be valid JSON matching the schema: "+err.Error())
	}
	return false
}

// fail переводит ошибки сервиса в HTTP-ответы. md5 нужен только для текста ошибки.
// Всё, что мы не ожидали, логируем и отдаём как 500, не раскрывая клиенту внутренности.
func (h *Handler) fail(w http.ResponseWriter, r *http.Request, err error, md5 string) {
	var ve *domain.ValidationError
	switch {
	case errors.As(err, &ve):
		httpjson.Error(w, http.StatusBadRequest, "Validation failed", strings.Join(ve.Problems, "; "))
	case errors.Is(err, domain.ErrNotFound):
		httpjson.Error(w, http.StatusNotFound, "Threat not found", "No threat with MD5 "+md5+" found")
	case errors.Is(err, domain.ErrAlreadyExists):
		httpjson.Error(w, http.StatusConflict, "Threat already exists", "Threat with MD5 "+md5+" already exists")
	default:
		h.log.Error("внутренняя ошибка", "method", r.Method, "path", r.URL.Path, "err", err)
		httpjson.Error(w, http.StatusInternalServerError, "Internal server error", "")
	}
}
