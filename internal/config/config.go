// Package config читает настройки сервиса из переменных окружения.
// Так проще всего настраивать контейнер: ничего не надо пересобирать.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
)

// Config — настройки сервиса.
type Config struct {
	Addr           string  // HTTP_ADDR, по умолчанию ":8080"
	DatabaseURL    string  // DATABASE_URL; пусто — данные хранятся в памяти
	APIKey         string  // API_KEY; пусто — авторизация выключена
	RateLimitRPS   float64 // RATE_LIMIT_RPS, по умолчанию 10; 0 — выключен
	RateLimitBurst int     // RATE_LIMIT_BURST, по умолчанию 20
	TLSCertFile    string  // TLS_CERT_FILE; вместе с TLS_KEY_FILE включает HTTPS
	TLSKeyFile     string  // TLS_KEY_FILE
}

// TLSEnabled говорит, нужно ли поднимать HTTPS.
func (c Config) TLSEnabled() bool {
	return c.TLSCertFile != "" && c.TLSKeyFile != ""
}

// Load собирает конфиг из окружения и проверяет его.
func Load() (Config, error) {
	return load(os.Getenv)
}

// load вынесена отдельно, чтобы в тестах не трогать настоящее окружение.
func load(get func(string) string) (Config, error) {
	c := Config{
		Addr:           withDefault(get("HTTP_ADDR"), ":8080"),
		DatabaseURL:    get("DATABASE_URL"),
		APIKey:         get("API_KEY"),
		RateLimitRPS:   10,
		RateLimitBurst: 20,
		TLSCertFile:    get("TLS_CERT_FILE"),
		TLSKeyFile:     get("TLS_KEY_FILE"),
	}

	if v := get("RATE_LIMIT_RPS"); v != "" {
		rps, err := strconv.ParseFloat(v, 64)
		if err != nil || rps < 0 {
			return Config{}, fmt.Errorf("RATE_LIMIT_RPS: ожидается неотрицательное число, получено %q", v)
		}
		c.RateLimitRPS = rps
	}
	if v := get("RATE_LIMIT_BURST"); v != "" {
		burst, err := strconv.Atoi(v)
		if err != nil || burst < 1 {
			return Config{}, fmt.Errorf("RATE_LIMIT_BURST: ожидается целое число не меньше 1, получено %q", v)
		}
		c.RateLimitBurst = burst
	}

	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return Config{}, errors.New("TLS_CERT_FILE и TLS_KEY_FILE нужно задавать вместе")
	}
	return c, nil
}

func withDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
