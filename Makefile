.PHONY: help tidy run build test test-integration vet up down certs

# Строка подключения к базе из docker-compose.yml (порт открыт на localhost).
TEST_DSN ?= postgres://threats:threats@localhost:5432/threats?sslmode=disable

help: ## Показать список команд
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-18s %s\n", $$1, $$2}'

tidy: ## Скачать зависимости и создать go.sum (делается один раз)
	go mod tidy

run: ## Запустить сервис локально (без БД: данные в памяти)
	go run ./cmd/server

build: ## Собрать бинарник в bin/server
	go build -o bin/server ./cmd/server

vet: ## Статическая проверка кода
	go vet ./...

test: ## Юнит- и интеграционные тесты (тесты Postgres пропускаются без БД)
	go test ./...

test-integration: ## Поднять Postgres в Docker и прогнать все тесты, включая хранилище
	docker compose up -d --wait db
	TEST_DATABASE_URL='$(TEST_DSN)' go test -count=1 ./...

up: ## Собрать и запустить сервис + Postgres в Docker
	docker compose up --build

down: ## Остановить контейнеры (данные БД сохраняются)
	docker compose down

certs: ## Выпустить самоподписанный сертификат для проверки HTTPS (certs/)
	mkdir -p certs
	openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
		-keyout certs/key.pem -out certs/cert.pem \
		-subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
