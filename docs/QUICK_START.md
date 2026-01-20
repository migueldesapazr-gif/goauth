# Quick Start Guide

GoAuth setup in a few minutes.

## Prerequisites

- Go 1.22+
- Postgres/MySQL/SQLite/MongoDB

## Install

```bash
go get github.com/migueldesapazr-gif/goauth
```

## Database Schema

Use:
- `docs/schema.sql` (Postgres)
- `docs/schema.mysql.sql`
- `docs/schema.sqlite.sql`

## Minimal Setup

```go
package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/migueldesapazr-gif/goauth"
)

func main() {
	db, err := pgxpool.New(context.Background(), os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}

	auth, err := goauth.New(
		goauth.WithDatabase(db),
		goauth.WithSecretsFromEnv(),
		goauth.WithSecurityMode(goauth.SecurityModeBalanced),
	)
	if err != nil {
		log.Fatal(err)
	}

	r := chi.NewRouter()
	r.Mount("/auth", auth.Handler())
	log.Fatal(http.ListenAndServe(":8080", r))
}
```

## Other Databases

```go
goauth.WithMySQLStore(usersDB, auditDB)
goauth.WithSQLiteStore(usersDB, auditDB)
goauth.WithMongoStore(mongoClient, "goauth")
```

Next:
- `CONFIGURATION.md`
- `API.md`
- `security.md`
