// Package service — бизнес-логика работы с угрозами.
//
// Сервис не знает ни про HTTP, ни про конкретную базу данных: с хранилищем он
// общается через интерфейс Repository. Поэтому в тестах подставляется
// хранилище в памяти, а в бою — Postgres.
package service

import (
	"context"
	"time"

	"threat-service/internal/domain"
)

// Repository — то, что сервису нужно от хранилища.
// Реализации обязаны возвращать domain.ErrNotFound и domain.ErrAlreadyExists
// в соответствующих случаях.
type Repository interface {
	// Create сохраняет новую угрозу. Если MD5 уже занят — domain.ErrAlreadyExists.
	Create(ctx context.Context, t domain.Threat) error
	// Get возвращает угрозу по MD5. Если её нет — domain.ErrNotFound.
	Get(ctx context.Context, md5 string) (domain.Threat, error)
	// Update заменяет данные угрозы (кроме md5 и created_at) и возвращает
	// запись целиком. Если угрозы нет — domain.ErrNotFound.
	Update(ctx context.Context, t domain.Threat) (domain.Threat, error)
}

// Service реализует операции над угрозами.
type Service struct {
	repo Repository
	now  func() time.Time // подменяется в тестах
}

// New создаёт сервис поверх переданного хранилища.
func New(repo Repository) *Service {
	return &Service{
		repo: repo,
		// Режем до микросекунд: именно такую точность хранит Postgres,
		// и так значения не «плывут» между хранилищами.
		now: func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) },
	}
}

// Create валидирует и сохраняет новую угрозу, выставляя служебные временные поля.
func (s *Service) Create(ctx context.Context, t domain.Threat) (domain.Threat, error) {
	t.Normalize()
	if err := t.Validate(); err != nil {
		return domain.Threat{}, err
	}

	now := s.now()
	t.CreatedAt, t.UpdatedAt = now, now

	if err := s.repo.Create(ctx, t); err != nil {
		return domain.Threat{}, err
	}
	return t, nil
}

// Get возвращает угрозу по MD5 (регистр буквы не важен).
func (s *Service) Get(ctx context.Context, md5 string) (domain.Threat, error) {
	md5, err := domain.ParseMD5(md5)
	if err != nil {
		return domain.Threat{}, err
	}
	return s.repo.Get(ctx, md5)
}

// Update полностью заменяет информацию об угрозе. Поля, которых нет в t,
// очищаются — так работает PUT. MD5 и дата создания остаются прежними.
func (s *Service) Update(ctx context.Context, md5 string, t domain.Threat) (domain.Threat, error) {
	md5, err := domain.ParseMD5(md5)
	if err != nil {
		return domain.Threat{}, err
	}

	t.MD5 = md5
	t.Normalize()
	if err := t.Validate(); err != nil {
		return domain.Threat{}, err
	}

	t.UpdatedAt = s.now()
	return s.repo.Update(ctx, t)
}
