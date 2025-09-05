version: "3.8"

services:
  curupira:
    container_name: curupira
    image: dwcorp/curupira:${app_version}
    environment:
      - APP_HOST=0.0.0.0
      - APP_PORT=8080
      - ISSUER=https://auth.dwcorp.com.br
      - DATABASE_URL=postgres://postgres:${postgres_password}@postgres:5432/authdb
      - COOKIE_DOMAIN=.dwcorp.com.br
      - SESSION_SECRET=${session_secret}
      - DEFAULT_ACCESS_TTL_SECS=3600
      - DEFAULT_REFRESH_TTL_MINS=43200
      - REQUIRE_API_KEY=true
    ports:
      - "8080:8080"
    networks:
      - postgres
    restart: unless-stopped
    depends_on:
      postgres:
        condition: service_healthy

  postgres:
    container_name: postgres_container
    image: postgres:15
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: ${postgres_password}
      POSTGRES_DB: authdb
      PGDATA: /data/postgres
    volumes:
      - postgres:/data/postgres
    ports:
      - "5432:5432"
    networks:
      - postgres
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres -d authdb"]
      interval: 10s
      timeout: 5s
      retries: 5

networks:
  postgres:
    driver: bridge

volumes:
  postgres:
