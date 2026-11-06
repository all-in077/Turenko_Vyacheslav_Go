// Package memory — хранилище угроз в оперативной памяти.
//
// Данные пропадают при перезапуске, поэтому для продакшена оно не годится.
// Зато удобно в тестах и для быстрого запуска сервиса без базы данных.
package memory

import (
	"context"
	"sync"

	"threat-service/internal/domain"
)

// Repo — потокобезопасное хранилище в памяти.
type Repo struct {
	mu    sync.RWMutex
	items map[string]domain.Threat
}

// New создаёт пустое хранилище.
func New() *Repo {
	return &Repo{items: make(map[string]domain.Threat)}
}

func (r *Repo) Create(_ context.Context, t domain.Threat) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.items[t.MD5]; exists {
		return domain.ErrAlreadyExists
	}
	r.items[t.MD5] = clone(t)
	return nil
}

func (r *Repo) Get(_ context.Context, md5 string) (domain.Threat, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	t, ok := r.items[md5]
	if !ok {
		return domain.Threat{}, domain.ErrNotFound
	}
	return clone(t), nil
}

func (r *Repo) Update(_ context.Context, t domain.Threat) (domain.Threat, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	old, ok := r.items[t.MD5]
	if !ok {
		return domain.Threat{}, domain.ErrNotFound
	}
	t.CreatedAt = old.CreatedAt // дата создания не должна меняться
	r.items[t.MD5] = clone(t)
	return clone(t), nil
}

// clone копирует угрозу вместе с указателем FileSize, чтобы снаружи
// нельзя было случайно изменить то, что лежит в хранилище.
func clone(t domain.Threat) domain.Threat {
	if t.FileSize != nil {
		v := *t.FileSize
		t.FileSize = &v
	}
	return t
}
