# ---- Стадия сборки ----
FROM golang:1.24-alpine AS build
# Если go.mod потребует более новую версию Go, она скачается автоматически.
ENV GOTOOLCHAIN=auto
WORKDIR /src

# Сначала зависимости: этот слой кешируется, пока go.mod/go.sum не менялись.
# (go.sum появляется после `go mod tidy`, см. README)
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# CGO выключен: получаем статический бинарник, которому не нужны системные библиотеки.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server

# ---- Финальный образ: только бинарник, без компилятора и исходников ----
FROM alpine:3.20
# Запускаем не от root: если в сервисе найдут уязвимость, у атакующего будет меньше прав.
RUN adduser -D -u 10001 app
USER app
COPY --from=build /out/server /usr/local/bin/server

EXPOSE 8080
# Для проверки живости используем wget из busybox (он есть в alpine).
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["server"]
