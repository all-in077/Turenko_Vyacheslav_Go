package handler

import (
	"time"

	"threat-service/internal/domain"
)

// Структуры ниже один в один повторяют схемы из api/openapi.yaml.

// threatFields — поля, общие для создания и обновления.
type threatFields struct {
	Name        string `json:"name"`
	SHA256      string `json:"sha256"`
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	FileSize    *int64 `json:"file_size"`
	Description string `json:"description"`
}

// createRequest — тело POST /info (схема ThreatCreateRequest).
type createRequest struct {
	MD5 string `json:"md5"`
	threatFields
}

// updateRequest — тело PUT /info/{md5} (схема ThreatUpdateRequest).
type updateRequest struct {
	threatFields
}

// threatResponse — ответ с информацией об угрозе (схема ThreatResponse).
// Необязательные поля, которые не заданы, в ответ не попадают.
type threatResponse struct {
	MD5         string    `json:"md5"`
	Name        string    `json:"name"`
	SHA256      string    `json:"sha256,omitempty"`
	Type        string    `json:"type,omitempty"`
	Severity    string    `json:"severity,omitempty"`
	FileSize    *int64    `json:"file_size,omitempty"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (f threatFields) toDomain(md5 string) domain.Threat {
	return domain.Threat{
		MD5:         md5,
		Name:        f.Name,
		SHA256:      f.SHA256,
		Type:        f.Type,
		Severity:    f.Severity,
		FileSize:    f.FileSize,
		Description: f.Description,
	}
}

func toResponse(t domain.Threat) threatResponse {
	return threatResponse{
		MD5:         t.MD5,
		Name:        t.Name,
		SHA256:      t.SHA256,
		Type:        t.Type,
		Severity:    t.Severity,
		FileSize:    t.FileSize,
		Description: t.Description,
		CreatedAt:   t.CreatedAt,
		UpdatedAt:   t.UpdatedAt,
	}
}
