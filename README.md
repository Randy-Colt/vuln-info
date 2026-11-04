# threat-info
API для обмена информацией об угрозах (malware). Сервис принимает и отдаёт сведения о файлах-угрозах: MD5-хеш, классификацию в формате Kaspersky (Trojan.Win32.Generic), размер и тип файла, время создания записи.

## Стек
- Go 1.27 — язык и рантайм.

- chi — HTTP-роутер.

- mattn/go-sqlite3 — драйвер SQLite (CGO).

- oapi-codegen — генерация серверного кода и DTO из OpenAPI-спецификации.

- slog — логирование.

- nethttp-middleware — валидация запросов по спецификации.

## Структура
```
├── cmd/threat_info/main.go  # точка входа
├── config/config.yml        # настрокйи приложения
├── docker/Dockerfile        # докерфайл
├── internal/
│   ├── api/                 # работа с HTTP API
│   │   ├── api.gen.go       # сгенерировано oapi-codegen
│   │   ├── api.go           # хендлеры
│   │   └── doc.go           # отдача json для SwaggerUI
│   ├── config/config.go     # пасрер конфигурации
│   ├── domain/              # доменная модель и сентинел-ошибки
│   ├── service/             # бизнес-логика
│   │   ├── threat_test.go   # unit тесты
│   │   ├── threat.go        # use cases
│   │   └── validators.go    # валидаторы и нормализаторы
│   └── storage/
│       ├── errors.go        # ошибки БД
│       ├── sqlite/          # реализация репозитория
│       └── models/          # БД-модель
└── openapi/
    ├── openapi.yml          # спецификация API
    └── oapi-codegen.yaml    # конфигурация генератора
```
## API
Полная спецификация — openapi/openapi.yml. Интерактивная документация — http://localhost:8080/docs/ после запуска.

# Имя угрозы
name парсится на три части по первым двум точкам: <behavior>.<platform>.<family>. Всё, что идёт после второй точки, попадает в family.

# Валидация двухуровневая:

md5 и file_size — проверяются nethttp-middleware по схеме из OpenAPI (pattern, minimum).
name проверяются в service.

## Запуск
Локально
bash
go run ./cmd/threat-info/main.go
Сервис слушает порт, переданный в конфиге, БД создаётся рядом как threats.db.

# Docker
```
docker build -t threat-info:dev .
docker run --rm -p 8000:8000 -v threat-info-data:/data threat-info:dev
```
Named volume threat-info-data монтируется в /data — БД переживает пересоздание контейнера.

## Тесты

# Всё, включая интеграционные
```
go test ./... -race -count=1
```
# Только юнит
```
go test ./... -short -race
```

## Решения и компромиссы
sql.Null[string] в DB-модели — нативная работа с NULL в SQLite. service и domain про database/sql не знают: конвертация живёт в storage/sqlite/convert.go.

Доменная модель с *string и time.Time — чистый Go, не зависит от драйвера. Если завтра сменить SQLite на Postgres, domain и service не изменятся.

Ошибки в трёх слоях: storage.Err* («нет строки в БД»), domain.Err* («нет сущности», «нарушено правило»), HTTP-коды в api. Маппинг между слоями — на границах.

updated_at убран — API и модель не возвращают поле. created_at ставится DEFAULT в схеме и возвращается через RETURNING из INSERT.

Prepared statements в Storage — переиспользуются между запросами. Для SQLite выигрыш в производительности минимален, но защита от SQL-инъекций и явный контракт запросов того стоят.

SetMaxOpenConns(1) — SQLite плохо переносит конкурентные записи (database is locked). Один коннект сериализует доступ и убирает ошибки. Для нагрузки с преобладанием чтения в проде понадобились бы раздельные пулы.

Валидатор + сервис — middleware отсекает синтаксический мусор до хендлера, сервис оставляет валидацию как «последнюю линию» для не-HTTP вызовов (тесты, будущий gRPC).

## Что можно улучшить
- PATCH для частичного обновления — сейчас PUT полностью заменяет запись.

- Раздельные пулы для чтения и записи SQLite, если появится нагрузка.

- Метрики (Prometheus) и трейсинг (OpenTelemetry) — сейчас есть только slog.

- HEALTHCHECK-эндпоинт — для docker-compose и k8s.

- Миграции (goose/golang-migrate) — сейчас схема создаётся через CREATE TABLE IF NOT EXISTS в New.
