# OIDC Proxy for Metabase/Nocobase

Универсальный OIDC прокси для аутентификации через внешние OIDC провайдеры (Google, Azure AD,
Keycloak, etc.).

## Инструменты:

1. Metabase (https://www.metabase.com/)
2. Nocobase (https://nocodb.com/)
3. Plane (https://plane.so)
4. Zabbix (https://www.zabbix.com)

## 🚀 Возможности

- 🔐 OIDC аутентификация для Metabase и Nocobase
- 👥 Автоматическое создание пользователей
- 🍪 Управление сессионными куками
- ⚡ Высокая производительность
- 🐳 Docker контейнер с минимальным образом
- 🔧 Гибкая конфигурация через переменные окружения

## 📦 Переменные окружения

### Обязательные настройки

| Переменная           | Описание                               | Пример                          |
|----------------------|----------------------------------------|---------------------------------|
| `LISTEN_ADDR`        | Адрес и порт для прослушивания         | `0.0.0.0:8000`                  |
| `EXTERNAL_URL`       | Внешний URL приложения                 | `https://analytics.example.com` |
| `TYPE`               | Тип бэкенда: `metabase` или `nocobase` | `metabase`                      |
| `PROXY_URL`          | URL целевого приложения                | `http://metabase:3000`          |
| `OIDC_ISSUER`        | URL OIDC провайдера                    | `https://accounts.google.com`   |
| `OIDC_CLIENT_ID`     | OIDC Client ID                         | `your-client-id`                |
| `OIDC_CLIENT_SECRET` | OIDC Client Secret                     | `your-client-secret`            |
| `STATE_SECRET`       | Секрет для подписи state параметров    | `your-secret-key`               |

### Настройки для Metabase

| Переменная                | Описание                       | Пример              |
|---------------------------|--------------------------------|---------------------|
| `METABASE_ADMIN_EMAIL`    | Email администратора Metabase  | `admin@example.com` |
| `METABASE_ADMIN_PASSWORD` | Пароль администратора Metabase | `secure-password`   |

### Настройки для Nocobase

| Переменная              | Описание                       | Пример              |
|-------------------------|--------------------------------|---------------------|
| `NOCODB_ADMIN_EMAIL`    | Email администратора Nocobase  | `admin@example.com` |
| `NOCODB_ADMIN_PASSWORD` | Пароль администратора Nocobase | `secure-password`   |

### Настройки для Plane

| Переменная  | Описание                     | Пример                     |
|-------------|------------------------------|----------------------------|
| `PLANE_DSN` | Строка до подключения к базе | `postgresql://db@db/plane` |

### Настройки для Zabbix

| Переменная     | Описание                                        | Пример                                 |
|----------------|-------------------------------------------------|----------------------------------------|
| `ZABBIX_TOKEN` | Токен API RPC для создания ролей и пользователя | `7ac5676d-13ea-4231-b40f-7d067b564d34` |

### Опциональные настройки

| Переменная              | Описание                    | По умолчанию           |
|-------------------------|-----------------------------|------------------------|
| `OIDC_SCOPE`            | OIDC scope (через запятую)  | `openid,email,profile` |
| `OIDC_PROMPT`           | OIDC prompt параметр        | -                      |
| `ALLOWED_EMAIL_DOMAINS` | Разрешенные домены email    | -                      |
| `ALLOWED_EMAILS`        | Список разрешенных email    | -                      |
| `SECURE_COOKIES`        | Использовать secure cookies | `true`                 |
| `LOG_LEVEL`             | Уровень логирования         | `info`                 |

## 🐳 Docker развертывание

### Сборка образа

```bash
# Клонируйте репозиторий
git clone https://github.com/your-username/any-oidc-proxy.git
cd any-oidc-proxy

# Соберите бинарник
make build

# Соберите Docker образ
make docker-build

# Запушите в registry
make docker-push
```

### Запуск контейнера

```bash
docker run -d \
  --name oidc-proxy \
  -p 8000:8000 \
  -e LISTEN_ADDR=0.0.0.0:8000 \
  -e EXTERNAL_URL=https://analytics.example.com \
  -e TYPE=metabase \
  -e PROXY_URL=http://metabase:3000 \
  -e METABASE_ADMIN_EMAIL=admin@example.com \
  -e METABASE_ADMIN_PASSWORD=secure-password \
  -e OIDC_ISSUER=https://accounts.google.com \
  -e OIDC_CLIENT_ID=your-client-id \
  -e OIDC_CLIENT_SECRET=your-client-secret \
  -e STATE_SECRET=your-secret-key \
  -e ALLOWED_EMAIL_DOMAINS=example.com \
  docker.io/maintainer64/any-oidc-proxy:latest
```

## 🔧 Локальная разработка

### Требования

- Go 1.21+
- Docker (опционально)

### Сборка бинарника

```bash
# Клонируйте репозиторий
git clone https://github.com/your-username/any-oidc-proxy.git
cd any-oidc-proxy

# Установите зависимости
go mod download

# Соберите бинарник
go build -o any-oidc-proxy .

# Запустите приложение
OIDC_ISSUER=https://accounts.google.com \
OIDC_CLIENT_ID=your-client-id \
OIDC_CLIENT_SECRET=your-client-secret \
STATE_SECRET=your-secret-key \
EXTERNAL_URL=http://localhost:8000 \
PROXY_URL=http://localhost:3000 \
TYPE=metabase \
METABASE_ADMIN_EMAIL=admin@example.com \
METABASE_ADMIN_PASSWORD=password \
./any-oidc-proxy
```

## 📁 Структура проекта

```
any-oidc-proxy/
├── cmd/
│   └── main.go          # Основное приложение
├── pkg/
│   ├── backend/         # Интерфейсы бэкендов
│   ├── metabase/        # Реализация для Metabase
│   ├── nocobase/        # Реализация для Nocobase
│   └── oidcauth/        # OIDC аутентификатор
├── Dockerfile           # Docker конфигурация
├── Makefile            # Утилиты сборки
├── go.mod              # Go зависимости
└── README.md           # Документация
```

## 📋 Пример docker-compose.yml

```yaml
version: '3.8'

services:
  oidc-proxy:
    image: docker.io/maintainer64/any-oidc-proxy:latest
    ports:
      - "8000:8000"
    environment:
      - LISTEN_ADDR=0.0.0.0:8000
      - EXTERNAL_URL=https://analytics.example.com
      - TYPE=metabase
      - PROXY_URL=http://metabase:3000
      - METABASE_ADMIN_EMAIL=admin@example.com
      - METABASE_ADMIN_PASSWORD=secure-password
      - OIDC_ISSUER=https://accounts.google.com
      - OIDC_CLIENT_ID=your-client-id
      - OIDC_CLIENT_SECRET=your-client-secret
      - STATE_SECRET=your-secret-key
      - ALLOWED_EMAIL_DOMAINS=example.com
    restart: unless-stopped

  metabase:
    image: metabase/metabase:latest
    ports:
      - "3000:3000"
    environment:
      - MB_DB_TYPE=postgres
      - MB_DB_DBNAME=metabase
      - MB_DB_PORT=5432
      - MB_DB_USER=metabase
      - MB_DB_PASS=password
      - MB_DB_HOST=postgres
    depends_on:
      - postgres

  postgres:
    image: postgres:13
    environment:
      - POSTGRES_DB=metabase
      - POSTGRES_USER=metabase
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:
```

## 🔐 Безопасность

- Все sensitive данные передаются через переменные окружения
- State параметры подписываются с использованием HMAC-SHA256
- Поддержка secure cookies
- Валидация доменов email
- OIDC токены проверяются через стандартный verifier

## 📊 Мониторинг

Приложение предоставляет health check endpoint:

```bash
curl http://localhost:8000/healthz
# ok
```

## 📄 Лицензия

Этот проект лицензирован под MIT License - смотрите файл [LICENSE](LICENSE) для деталей.

---

⭐ Если этот проект был полезен, поставьте звезду на GitHub!
