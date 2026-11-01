# threat-info
API для обмена информацией об угрозах (malware). Сервис принимает и отдаёт сведения о файлах-угрозах: MD5-хеш, классификацию в формате Kaspersky (Trojan.Win32.Generic), размер и тип файла, время создания записи.

## Стек
- Go 1.27 — язык и рантайм.

- chi — HTTP-роутер.

- mattn/go-sqlite3 — драйвер SQLite (CGO).

- oapi-codegen — генерация серверного кода и DTO из OpenAPI-спецификации.

- slog — структурированное логирование.

- nethttp-middleware — валидация запросов по спецификации.

## Архитектура
text
             ┌─────────────┐
HTTP/JSON ──▶│  api        │  chi + strict-server + validator
             │  (handler)  │  маппинг api.* ↔ domain.*
             └──────┬──────┘
                    │
                    ▼
             ┌─────────────┐
             │  service    │  валидация, парсинг name, нормализация
             │  (Threat)   │  маппинг storage.Err* → domain.Err*
             └──────┬──────┘
                    │
                    ▼
             ┌─────────────┐
             │  storage    │  SQL, prepared statements
             │  (sqlite)   │  маппинг models.Threat ↔ domain.Threat
             └─────────────┘
Направление зависимостей — строго сверху вниз. api не импортирует storage, service не импортирует sqlite. Транспортные DTO (api.*) не протекают в бизнес-логику.

## Структура
text
.
├── cmd/threat-info/         # точка входа
├── internal/
│   ├── api/                 # HTTP-хендлеры, маппинг ошибок в ответы
│   │   └── api.gen.go       # сгенерировано oapi-codegen, не правится руками
│   ├── config/              # загрузка конфигурации
│   ├── domain/              # доменная модель и сентинел-ошибки
│   ├── service/             # бизнес-логика
│   └── storage/
│       ├── sqlite/          # реализация репозитория
│       └── models/          # DB-модель (sql.Null[string], time.Time)
├── openapi/openapi.yml      # спецификация API
└── oapi-codegen.yaml        # конфигурация генератора

## API
Полная спецификация — openapi/openapi.yml. Интерактивная документация — http://localhost:8080/docs/ после запуска.

Метод	Путь	Назначение
GET	/info/{md5}	Получить запись по MD5
POST	/info	Создать запись
PUT	/info/{md5}	Обновить запись (полная замена)
Примеры
### Создание
```
curl -X POST http://localhost:8080/info \
  -H 'Content-Type: application/json' \
  -d '{"md5":"d41d8cd98f00b204e9800998ecf8427e","name":"Trojan.Win32.Generic","file_size":1024,"file_type":"pe"}'
```

# Получение
```
curl http://localhost:8080/info/d41d8cd98f00b204e9800998ecf8427e
```

# Обновление
curl -X PUT http://localhost:8080/info/d41d8cd98f00b204e9800998ecf8427e \
  -H 'Content-Type: application/json' \
  -d '{"name":"Worm.Linux.Mirai","file_size":2048}'
Ответы
2xx — успех, тело — ThreatResponse.

400 — невалидный MD5/имя/размер ({message, details}).

404 — запись не найдена.

409 — MD5 уже существует (только POST).

500 — внутренняя ошибка.

# Имя угрозы
name парсится на три части по первым двум точкам: <behavior>.<platform>.<family>. Всё, что идёт после второй точки, попадает в family.

# Валидация двухуровневая:

md5 и file_size — проверяются nethttp-middleware по схеме из OpenAPI (pattern, minimum). До хендлера не доходят.

name и бизнес-правила — проверяются в service. В спеке у name нет pattern, только описание формата.

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
# Только юнит (интеграционные пропускаются через testing.Short)
```
go test ./... -short -race
```
Юнит-тесты (internal/service) — бизнес-логика с фейковым репозиторием: нормализация MD5, парсинг имени, нормализация file_type, маппинг ошибок.

Интеграционные (internal/storage/sqlite) — service + real SQLite в t.TempDir(): SQL, RETURNING, DEFAULT created_at, sql.Null[string].

E2E (internal/api) — полный стек через httptest: chi, валидатор по спеке, strict-server, JSON и коды ответов.

## Кодогенерация
После правки openapi/openapi.yml:

```
oapi-codegen -config openapi/oapi-codegen.yaml openapi/openapi.yml
```

Конфигурация (oapi-codegen.yaml):

```
package: api
output: internal/api/api.gen.go
generate:
  chi-server: true
  strict-server: true
  models: true
  embedded-spec: true
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
