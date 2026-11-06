// Package postgres — хранилище угроз в PostgreSQL (драйвер pgx).
package postgres

import (
	"context"
	_ "embed"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"threat-service/internal/domain"
)

// Схема лежит рядом в schema.sql и вшивается в бинарник при сборке.
//
//go:embed schema.sql
var schema string

// Код ошибки Postgres «нарушено ограничение уникальности».
const uniqueViolation = "23505"

// Список колонок в одном месте, чтобы INSERT, SELECT и RETURNING не разъехались.
const columns = `md5, name, sha256, threat_type, severity, file_size, description, created_at, updated_at`

// Repo — хранилище на пуле соединений pgx.
type Repo struct {
	pool *pgxpool.Pool
}

// New подключается к базе, проверяет связь и создаёт таблицу, если её ещё нет.
func New(ctx context.Context, dsn string) (*Repo, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("подключение к postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres не отвечает: %w", err)
	}
	if _, err := pool.Exec(ctx, schema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("применение схемы: %w", err)
	}
	return &Repo{pool: pool}, nil
}

// Close закрывает все соединения.
func (r *Repo) Close() {
	r.pool.Close()
}

// Create добавляет новую угрозу. Дубликат определяем по первичному ключу.
func (r *Repo) Create(ctx context.Context, t domain.Threat) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO threats (`+columns+`) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		t.MD5, t.Name, t.SHA256, t.Type, t.Severity, t.FileSize, t.Description, t.CreatedAt, t.UpdatedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
			return domain.ErrAlreadyExists
		}
		return fmt.Errorf("добавление угрозы: %w", err)
	}
	return nil
}

// Get возвращает угрозу по MD5.
func (r *Repo) Get(ctx context.Context, md5 string) (domain.Threat, error) {
	row := r.pool.QueryRow(ctx, `SELECT `+columns+` FROM threats WHERE md5 = $1`, md5)
	t, err := scan(row)
	if err != nil {
		return domain.Threat{}, fmt.Errorf("чтение угрозы: %w", err)
	}
	return t, nil
}

// Update заменяет данные угрозы. md5 и created_at не трогаем.
// RETURNING отдаёт итоговую запись одним запросом, без лишнего SELECT.
func (r *Repo) Update(ctx context.Context, t domain.Threat) (domain.Threat, error) {
	row := r.pool.QueryRow(ctx,
		`UPDATE threats
		    SET name = $2, sha256 = $3, threat_type = $4, severity = $5,
		        file_size = $6, description = $7, updated_at = $8
		  WHERE md5 = $1
		RETURNING `+columns,
		t.MD5, t.Name, t.SHA256, t.Type, t.Severity, t.FileSize, t.Description, t.UpdatedAt,
	)
	updated, err := scan(row)
	if err != nil {
		return domain.Threat{}, fmt.Errorf("обновление угрозы: %w", err)
	}
	return updated, nil
}

// scan читает одну строку. Отсутствие строки превращаем в domain.ErrNotFound.
func scan(row pgx.Row) (domain.Threat, error) {
	var t domain.Threat
	err := row.Scan(
		&t.MD5, &t.Name, &t.SHA256, &t.Type, &t.Severity,
		&t.FileSize, // NULL в базе станет nil
		&t.Description, &t.CreatedAt, &t.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Threat{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.Threat{}, err
	}
	// Драйвер отдаёт время в локальной зоне, а мы везде работаем в UTC.
	t.CreatedAt = t.CreatedAt.UTC()
	t.UpdatedAt = t.UpdatedAt.UTC()
	return t, nil
}
