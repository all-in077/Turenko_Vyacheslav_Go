// Package domain описывает, что такое угроза и какие данные о ней считаются корректными.
//
// Тут намеренно нет ничего про HTTP и базу данных: только модель и правила.
// Благодаря этому её легко тестировать и переиспользовать.
package domain

import (
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// Ограничения на поля. Они же прописаны в api/openapi.yaml.
const (
	MaxNameLen        = 255
	MaxDescriptionLen = 2000
)

// Допустимые значения полей-перечислений.
var (
	threatTypes = []string{"trojan", "ransomware", "worm", "virus", "backdoor", "spyware", "adware", "miner", "other"}
	severities  = []string{"low", "medium", "high", "critical"}
)

var (
	md5Re    = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)
	sha256Re = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
)

// Ошибки, которые возвращают хранилища и сервис. Слой HTTP превращает их в коды ответа.
var (
	// ErrNotFound — угрозы с таким MD5 нет.
	ErrNotFound = errors.New("threat not found")
	// ErrAlreadyExists — угроза с таким MD5 уже есть.
	ErrAlreadyExists = errors.New("threat already exists")
)

// ValidationError собирает сразу все найденные проблемы,
// чтобы клиенту не приходилось исправлять их по одной.
type ValidationError struct {
	Problems []string
}

func (e *ValidationError) Error() string {
	return "validation failed: " + strings.Join(e.Problems, "; ")
}

// Threat — информация об угрозе.
//
// Необязательные поля, если их не задали, содержат пустую строку (а FileSize — nil).
// Размер файла сделан указателем, потому что 0 — вполне настоящее значение
// (например, у пустого файла как раз MD5 d41d8cd9...).
type Threat struct {
	MD5         string
	Name        string
	SHA256      string
	Type        string
	Severity    string
	FileSize    *int64
	Description string

	// Служебные поля: выставляет сервер, клиент их не передаёт.
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ParseMD5 проверяет MD5 и приводит его к нижнему регистру,
// чтобы «ABC…» и «abc…» считались одной и той же записью.
func ParseMD5(s string) (string, error) {
	if !md5Re.MatchString(s) {
		return "", &ValidationError{Problems: []string{"md5: must be 32 hexadecimal characters"}}
	}
	return strings.ToLower(s), nil
}

// Normalize приводит поля к каноничному виду. Вызывать до Validate.
// Хеши переводим в нижний регистр, из текстовых полей убираем лишние пробелы по краям.
// Перечисления (type, severity) не трогаем: по спеке допустимы только значения в нижнем регистре.
func (t *Threat) Normalize() {
	t.MD5 = strings.ToLower(t.MD5)
	t.SHA256 = strings.ToLower(t.SHA256)
	t.Name = strings.TrimSpace(t.Name)
	t.Description = strings.TrimSpace(t.Description)
}

// Validate проверяет все поля и возвращает *ValidationError со списком проблем.
func (t Threat) Validate() error {
	var p []string

	if !md5Re.MatchString(t.MD5) {
		p = append(p, "md5: must be 32 hexadecimal characters")
	}

	if t.Name == "" {
		p = append(p, "name: is required")
	} else if utf8.RuneCountInString(t.Name) > MaxNameLen {
		p = append(p, "name: must be at most 255 characters")
	}

	if t.SHA256 != "" && !sha256Re.MatchString(t.SHA256) {
		p = append(p, "sha256: must be 64 hexadecimal characters")
	}

	if t.Type != "" && !slices.Contains(threatTypes, t.Type) {
		p = append(p, "type: must be one of "+strings.Join(threatTypes, ", "))
	}

	if t.Severity != "" && !slices.Contains(severities, t.Severity) {
		p = append(p, "severity: must be one of "+strings.Join(severities, ", "))
	}

	if t.FileSize != nil && *t.FileSize < 0 {
		p = append(p, "file_size: must not be negative")
	}

	if utf8.RuneCountInString(t.Description) > MaxDescriptionLen {
		p = append(p, "description: must be at most 2000 characters")
	}

	if len(p) > 0 {
		return &ValidationError{Problems: p}
	}
	return nil
}
