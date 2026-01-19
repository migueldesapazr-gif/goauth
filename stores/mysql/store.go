// Package mysql provides a MySQL implementation of the goauth.Store interface.
package mysql

import (
	"database/sql"

	"github.com/migueldesapazr-gif/goauth/stores/sqlstore"
)

// New creates a new MySQL store using the same DB for users and audit logs.
func New(db *sql.DB) *sqlstore.Store {
	return sqlstore.New(db, db)
}

// NewWithAudit creates a new MySQL store with separate connections.
func NewWithAudit(users, audit *sql.DB) *sqlstore.Store {
	return sqlstore.New(users, audit)
}
