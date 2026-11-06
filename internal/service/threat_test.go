package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"threat-service/internal/domain"
	"threat-service/internal/storage/memory"
)

const testMD5 = "d41d8cd98f00b204e9800998ecf8427e"

func ptr[T any](v T) *T { return &v }

// newTestService возвращает сервис с хранилищем в памяти и управляемыми часами.
func newTestService() (*Service, *time.Time) {
	svc := New(memory.New())
	clock := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return clock }
	return svc, &clock
}

func TestCreateAndGet(t *testing.T) {
	svc, clock := newTestService()
	ctx := context.Background()

	created, err := svc.Create(ctx, domain.Threat{
		MD5:      strings.ToUpper(testMD5), // в верхнем регистре, должно сохраниться в нижнем
		Name:     "  Trojan.Win32.Generic ",
		Severity: "high",
		FileSize: ptr(int64(0)),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.MD5 != testMD5 || created.Name != "Trojan.Win32.Generic" {
		t.Errorf("поля не нормализованы: %+v", created)
	}
	if !created.CreatedAt.Equal(*clock) || !created.UpdatedAt.Equal(*clock) {
		t.Errorf("служебные даты не выставлены: %+v", created)
	}

	// Достаём и по нижнему, и по верхнему регистру — это одна и та же запись.
	for _, key := range []string{testMD5, strings.ToUpper(testMD5)} {
		got, err := svc.Get(ctx, key)
		if err != nil {
			t.Fatalf("Get(%s): %v", key, err)
		}
		if got.Name != "Trojan.Win32.Generic" || got.FileSize == nil || *got.FileSize != 0 {
			t.Errorf("Get(%s) вернул не то: %+v", key, got)
		}
	}
}

func TestCreateValidation(t *testing.T) {
	svc, _ := newTestService()

	_, err := svc.Create(context.Background(), domain.Threat{MD5: "bad", Name: ""})
	var ve *domain.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("ожидали ValidationError, получили %v", err)
	}
}

func TestCreateDuplicate(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()
	th := domain.Threat{MD5: testMD5, Name: "A"}

	if _, err := svc.Create(ctx, th); err != nil {
		t.Fatalf("первый Create: %v", err)
	}
	// Тот же хеш в другом регистре — тоже дубликат.
	th.MD5 = strings.ToUpper(testMD5)
	if _, err := svc.Create(ctx, th); !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("ожидали ErrAlreadyExists, получили %v", err)
	}
}

func TestGetErrors(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	if _, err := svc.Get(ctx, testMD5); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("ожидали ErrNotFound, получили %v", err)
	}
	var ve *domain.ValidationError
	if _, err := svc.Get(ctx, "not-an-md5"); !errors.As(err, &ve) {
		t.Errorf("ожидали ValidationError, получили %v", err)
	}
}

func TestUpdate(t *testing.T) {
	svc, clock := newTestService()
	ctx := context.Background()
	created := *clock

	if _, err := svc.Create(ctx, domain.Threat{
		MD5: testMD5, Name: "Old", Severity: "low", Description: "старое описание",
	}); err != nil {
		t.Fatal(err)
	}

	*clock = clock.Add(time.Hour)
	updated, err := svc.Update(ctx, testMD5, domain.Threat{Name: "New", Type: "worm"})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}

	if updated.Name != "New" || updated.Type != "worm" {
		t.Errorf("поля не обновились: %+v", updated)
	}
	// PUT заменяет запись целиком: поля, которых нет в запросе, очищаются.
	if updated.Severity != "" || updated.Description != "" {
		t.Errorf("необязательные поля должны были очиститься: %+v", updated)
	}
	if !updated.CreatedAt.Equal(created) {
		t.Errorf("created_at изменился: %v", updated.CreatedAt)
	}
	if !updated.UpdatedAt.Equal(clock.UTC()) {
		t.Errorf("updated_at не обновился: %v", updated.UpdatedAt)
	}

	got, _ := svc.Get(ctx, testMD5)
	if got.Name != "New" {
		t.Errorf("изменения не сохранились: %+v", got)
	}
}

func TestUpdateErrors(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()
	var ve *domain.ValidationError

	if _, err := svc.Update(ctx, testMD5, domain.Threat{Name: "X"}); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("несуществующая запись: ожидали ErrNotFound, получили %v", err)
	}
	if _, err := svc.Update(ctx, "bad", domain.Threat{Name: "X"}); !errors.As(err, &ve) {
		t.Errorf("плохой md5: ожидали ValidationError, получили %v", err)
	}
	if _, err := svc.Update(ctx, testMD5, domain.Threat{Name: ""}); !errors.As(err, &ve) {
		t.Errorf("пустое имя: ожидали ValidationError, получили %v", err)
	}
}

// Ошибки хранилища должны доходить до вызывающего как есть.
func TestRepositoryErrorPropagates(t *testing.T) {
	boom := errors.New("база упала")
	svc := New(brokenRepo{err: boom})

	if _, err := svc.Create(context.Background(), domain.Threat{MD5: testMD5, Name: "A"}); !errors.Is(err, boom) {
		t.Errorf("ожидали ошибку хранилища, получили %v", err)
	}
}

type brokenRepo struct{ err error }

func (b brokenRepo) Create(context.Context, domain.Threat) error { return b.err }
func (b brokenRepo) Get(context.Context, string) (domain.Threat, error) {
	return domain.Threat{}, b.err
}
func (b brokenRepo) Update(context.Context, domain.Threat) (domain.Threat, error) {
	return domain.Threat{}, b.err
}
