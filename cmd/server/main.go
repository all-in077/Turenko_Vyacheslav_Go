// Command server запускает REST-сервис обмена информацией об угрозах.
//
// Настройки читаются из переменных окружения (см. internal/config и README).
// Без DATABASE_URL сервис работает на хранилище в памяти — удобно для быстрого запуска.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"threat-service/internal/config"
	"threat-service/internal/server"
	"threat-service/internal/service"
	"threat-service/internal/storage/memory"
	"threat-service/internal/storage/postgres"
)

func main() {
	if err := run(); err != nil {
		slog.Error("сервис остановился с ошибкой", "err", err)
		os.Exit(1)
	}
}

func run() error {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	// Ctrl+C или SIGTERM от Docker запускают аккуратное завершение.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	repo, closeRepo, err := openStorage(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer closeRepo()

	handler := server.New(service.New(repo), server.Options{
		Logger:         log,
		APIKey:         cfg.APIKey,
		RateLimitRPS:   cfg.RateLimitRPS,
		RateLimitBurst: cfg.RateLimitBurst,
	})

	srv := &http.Server{
		Addr:    cfg.Addr,
		Handler: handler,
		// Таймауты защищают от «медленных» клиентов, которые держат соединения открытыми.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	if cfg.APIKey == "" {
		log.Warn("API_KEY не задан: авторизация выключена, API открыт всем")
	}

	serveErr := make(chan error, 1)
	go func() {
		log.Info("сервис запущен", "addr", cfg.Addr, "tls", cfg.TLSEnabled())
		if cfg.TLSEnabled() {
			serveErr <- srv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
			serveErr <- srv.ListenAndServe()
		}
	}()

	select {
	case err := <-serveErr:
		// Сюда попадаем, только если сервер не смог стартовать (например, порт занят).
		return err
	case <-ctx.Done():
		log.Info("получен сигнал остановки, завершаем работу")
	}

	// Даём текущим запросам до 10 секунд, чтобы они успели завершиться.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return err
	}
	if err := <-serveErr; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	log.Info("сервис остановлен")
	return nil
}

// openStorage выбирает хранилище по конфигу и возвращает функцию для его закрытия.
func openStorage(ctx context.Context, cfg config.Config, log *slog.Logger) (service.Repository, func(), error) {
	if cfg.DatabaseURL == "" {
		log.Warn("DATABASE_URL не задан: данные хранятся в памяти и пропадут при перезапуске")
		return memory.New(), func() {}, nil
	}

	repo, err := postgres.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, nil, err
	}
	log.Info("подключились к postgres")
	return repo, repo.Close, nil
}
