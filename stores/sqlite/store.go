// Package sqlite provides a SQLite implementation of the goauth.Store interface.
package sqlite

import (
	"database/sql"

	"github.com/migueldesapazr-gif/goauth/stores/sqlstore"
)

// New creates a new SQLite store using the same DB for users and audit logs.
func New(db *sql.DB) *sqlstore.Store {
	return sqlstore.New(db, db)
}

// NewWithAudit creates a new SQLite store with separate connections.
func NewWithAudit(users, audit *sql.DB) *sqlstore.Store {
	return sqlstore.New(users, audit)
}
