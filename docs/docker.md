# GoAuth Docker Quickstart

Deploy GoAuth with Docker in minutes.

## Files Needed

### docker-compose.yml

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_USER: goauth
      POSTGRES_PASSWORD: ${DB_PASSWORD:-supersecret}
      POSTGRES_DB: goauth
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./docs/schema.sql:/docker-entrypoint-initdb.d/01-schema.sql
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U goauth"]
      interval: 5s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 5s
      retries: 5

  goauth:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "8080:8080"
    environment:
      DATABASE_URL: postgres://goauth:${DB_PASSWORD:-supersecret}@postgres:5432/goauth?sslmode=disable
      REDIS_URL: redis:6379
      GOAUTH_JWT_SECRET: ${JWT_SECRET}
      GOAUTH_ENCRYPTION_KEY: ${ENCRYPTION_KEY}
      GOAUTH_PEPPER: ${PEPPER}
      GOAUTH_APP_NAME: ${APP_NAME:-My App}
      GOAUTH_APP_URL: ${APP_URL:-http://localhost:8080}
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    restart: unless-stopped

volumes:
  postgres_data:
  redis_data:
```

### Dockerfile

```dockerfile
FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags='-w -s' -o /goauth ./cmd/server

FROM alpine:3.19
RUN apk --no-cache add ca-certificates tzdata
COPY --from=builder /goauth /goauth

EXPOSE 8080
ENTRYPOINT ["/goauth"]
```

### .env

```bash
# Generate these with: openssl rand -base64 32
JWT_SECRET=your-jwt-secret-here
ENCRYPTION_KEY=your-encryption-key-here
PEPPER=your-pepper-here

# App
APP_NAME=My App
APP_URL=https://myapp.com
DB_PASSWORD=supersecret

# Optional - OAuth
GOAUTH_GOOGLE_CLIENT_ID=xxx
GOAUTH_GOOGLE_CLIENT_SECRET=xxx
```

## Quick Start

```bash
# Generate secrets
export JWT_SECRET=$(openssl rand -base64 32)
export ENCRYPTION_KEY=$(openssl rand -base64 32)
export PEPPER=$(openssl rand -base64 32)

# Start services
docker-compose up -d

# Check logs
docker-compose logs -f goauth
```

## Kubernetes

### ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: goauth-config
data:
  GOAUTH_APP_NAME: "My App"
  GOAUTH_APP_URL: "https://myapp.com"
```

### Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: goauth-secrets
type: Opaque
stringData:
  JWT_SECRET: "base64-encoded-secret"
  ENCRYPTION_KEY: "base64-encoded-key"
  PEPPER: "base64-encoded-pepper"
```

### Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: goauth
spec:
  replicas: 3
  selector:
    matchLabels:
      app: goauth
  template:
    metadata:
      labels:
        app: goauth
    spec:
      containers:
      - name: goauth
        image: your-registry/goauth:latest
        ports:
        - containerPort: 8080
        envFrom:
        - configMapRef:
            name: goauth-config
        - secretRef:
            name: goauth-secrets
        resources:
          requests:
            memory: "64Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /auth/health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /auth/health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
```

## Health Checks

```bash
# Check health
curl http://localhost:8080/auth/health

# Expected response
{"status":"ok","version":"2.0"}
```

## Scaling

GoAuth is stateless and horizontally scalable:

1. Use Redis for rate limiting and token blacklist
2. Use PostgreSQL for data persistence
3. Deploy multiple replicas behind a load balancer
4. All instances share the same secrets
