package database

import (
	"context"
	"database/sql"
	"embed"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

func Connect(ctx context.Context, dbURL string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dbURL)
	if err != nil {
		return nil, err
	}

	d, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return nil, err
	}

	migrationInstance, err := sqlite.WithInstance(db, &sqlite.Config{})
	if err != nil {
		return nil, err
	}

	migrator, err := migrate.NewWithInstance("iofs", d, "sqlite", migrationInstance)
	if err != nil {
		return nil, err
	}
	migrator.Up()

	return db, nil
}
