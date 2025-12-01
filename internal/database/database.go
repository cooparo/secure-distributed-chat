package database

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"path/filepath"

	"github.com/cooparo/secure-distributed-chat/internal/database/repository"
	"github.com/cooparo/secure-distributed-chat/internal/xdg"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

func Connect(ctx context.Context, dbURI string) (*repository.Queries, error) {
	db, err := sql.Open("sqlite", dbURI)
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
	if err := migrator.Up(); err != nil {
		if !errors.Is(err, migrate.ErrNoChange) {
			return nil, err
		}
	}

	q := repository.New(db)

	return q, nil
}

func MakeDBURI() (string, error) {
	dir, err := xdg.GetDataHome()
	if err != nil {
		return "", err
	}

	path := filepath.Join(dir, "db")
	return "file://" + path + "?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)", nil
}
