package postgres

// Интеграционные тесты хранилища на настоящем Postgres.
// Без переменной TEST_DATABASE_URL они пропускаются, так что обычный
// `go test ./...` работает и без базы. Запустить с базой: make test-integration.

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"threat-service/internal/domain"
)

const testMD5 = "d41d8cd98f00b204e9800998ecf8427e"

func newTestRepo(t *testing.T) *Repo {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL не задан, интеграционные тесты Postgres пропущены")
	}

	ctx := context.Background()
	repo, err := New(ctx, dsn)
	if err != nil {
		t.Fatalf("подключение: %v", err)
	}
	t.Cleanup(repo.Close)

	// Каждый тест начинает с чистой таблицы.
	if _, err := repo.pool.Exec(ctx, `TRUNCATE threats`); err != nil {
		t.Fatalf("очистка таблицы: %v", err)
	}
	return repo
}

func TestCreateGet(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	size := int64(0) // ноль — настоящее значение, не «пусто»
	now := time.Now().UTC().Truncate(time.Microsecond)
	in := domain.Threat{
		MD5: testMD5, Name: "Trojan", SHA256: "", Type: "trojan", Severity: "high",
		FileSize: &size, Description: "описание", CreatedAt: now, UpdatedAt: now,
	}
	if err := repo.Create(ctx, in); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := repo.Get(ctx, testMD5)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != "Trojan" || got.Type != "trojan" || got.Severity != "high" || got.Description != "описание" {
		t.Errorf("поля не совпали: %+v", got)
	}
	if got.FileSize == nil || *got.FileSize != 0 {
		t.Errorf("file_size: %v", got.FileSize)
	}
	if !got.CreatedAt.Equal(now) {
		t.Errorf("created_at: %v, ожидали %v", got.CreatedAt, now)
	}
}

func TestNullFileSize(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)

	if err := repo.Create(ctx, domain.Threat{MD5: testMD5, Name: "A", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	got, err := repo.Get(ctx, testMD5)
	if err != nil {
		t.Fatal(err)
	}
	if got.FileSize != nil {
		t.Errorf("file_size должен быть nil, а не %d", *got.FileSize)
	}
}

func TestCreateDuplicate(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()
	now := time.Now().UTC()
	th := domain.Threat{MD5: testMD5, Name: "A", CreatedAt: now, UpdatedAt: now}

	if err := repo.Create(ctx, th); err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(ctx, th); !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("ожидали ErrAlreadyExists, получили %v", err)
	}
}

func TestGetNotFound(t *testing.T) {
	repo := newTestRepo(t)
	if _, err := repo.Get(context.Background(), testMD5); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("ожидали ErrNotFound, получили %v", err)
	}
}

func TestUpdate(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()
	created := time.Now().UTC().Truncate(time.Microsecond)

	if err := repo.Create(ctx, domain.Threat{
		MD5: testMD5, Name: "Old", Severity: "low", CreatedAt: created, UpdatedAt: created,
	}); err != nil {
		t.Fatal(err)
	}

	later := created.Add(time.Hour)
	updated, err := repo.Update(ctx, domain.Threat{MD5: testMD5, Name: "New", Type: "worm", UpdatedAt: later})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Name != "New" || updated.Type != "worm" || updated.Severity != "" {
		t.Errorf("поля после обновления: %+v", updated)
	}
	if !updated.CreatedAt.Equal(created) {
		t.Errorf("created_at изменился: %v", updated.CreatedAt)
	}
	if !updated.UpdatedAt.Equal(later) {
		t.Errorf("updated_at: %v", updated.UpdatedAt)
	}
}

func TestUpdateNotFound(t *testing.T) {
	repo := newTestRepo(t)
	_, err := repo.Update(context.Background(), domain.Threat{MD5: testMD5, Name: "X", UpdatedAt: time.Now()})
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("ожидали ErrNotFound, получили %v", err)
	}
}
