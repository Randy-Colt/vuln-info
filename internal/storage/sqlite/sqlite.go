package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"threat-info/internal/domain"
	"threat-info/internal/storage"
	"threat-info/internal/storage/models"

	"github.com/mattn/go-sqlite3"
)


type Storage struct {
    db *sql.DB
    getThreatStmt *sql.Stmt
    setThreatStmt *sql.Stmt
    updateThreatStmt *sql.Stmt
}


func New(storagePath string) (*Storage, error) {
    const op = "storage.sqlite.New"

    db, err := sql.Open("sqlite3", storagePath)
    if err != nil {
        return nil, fmt.Errorf("%s: %w", op, err)
    }
    db.SetMaxOpenConns(1)


    if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("%s: ping: %w", op, err)
	}

    _, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS threat(
            md5         TEXT PRIMARY KEY CHECK (length(md5) = 32),
            behavior    TEXT NOT NULL,
            platform    TEXT NOT NULL,
            family      TEXT NOT NULL,
            file_size   INTEGER NOT NULL,
            file_type   TEXT,
            created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        );
    `)
    if err != nil {
        return nil, fmt.Errorf("%s: %w", op, err)
    }

	getStmt, err := db.Prepare(`
		SELECT md5, behavior, platform, family, file_size, file_type, created_at, updated_at
		FROM threat WHERE md5 = ?`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("%s: prepare get: %w", op, err)
	}

	setStmt, err := db.Prepare(`
		INSERT INTO threat (md5, behavior, platform, family, file_size, file_type)
		VALUES (?, ?, ?, ?, ?, ?)
        RETURNING md5, behavior, platform, family, file_size, file_type, created_at`)
	if err != nil {
		getStmt.Close()
		db.Close()
		return nil, fmt.Errorf("%s: prepare insert: %w", op, err)
	}

	updateStmt, err := db.Prepare(`
		UPDATE threat
		SET behavior = ?, platform = ?, family = ?, file_size = ?, file_type = ?
		WHERE md5 = ?
        RETURNING md5, behavior, platform, family, file_size, file_type, created_at`)
	if err != nil {
		getStmt.Close()
		setStmt.Close()
		db.Close()
		return nil, fmt.Errorf("%s: prepare update: %w", op, err)
	}

	return &Storage{
		db:               db,
		getThreatStmt:    getStmt,
		setThreatStmt:    setStmt,
		updateThreatStmt: updateStmt,
	}, nil
}


func (s *Storage) Threat(ctx context.Context, md5Hash string) (domain.Threat, error) {
    const op = "storage.sqlite.Threat"

	row := s.getThreatStmt.QueryRowContext(ctx, md5Hash)

	var m models.Threat
	err := row.Scan(
		&m.MD5, &m.Behavior, &m.Platform, &m.Family,
		&m.FileSize, &m.FileType, &m.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.Threat{}, fmt.Errorf("%s: %w", op, storage.ErrThreatNotFound)
		}
		return domain.Threat{}, fmt.Errorf("%s: scan: %w", op, err)
	}

	return toDomain(m), nil
}

func (s *Storage) Create(ctx context.Context, t domain.Threat) (domain.Threat, error) {
	const op = "storage.sqlite.Create"

	m := toModel(t)
	err := s.setThreatStmt.QueryRowContext(ctx,
		m.MD5, m.Behavior, m.Platform, m.Family, m.FileSize, m.FileType,
	).Scan(
		&m.MD5, &m.Behavior, &m.Platform, &m.Family,
		&m.FileSize, &m.FileType, &m.CreatedAt,
	)

	if err != nil {
		if sqliteErr, ok := errors.AsType[sqlite3.Error](err); ok {
			if sqliteErr.ExtendedCode == sqlite3.ErrConstraintPrimaryKey {
				return domain.Threat{}, fmt.Errorf("%s: %w", op, storage.ErrThreatExists)
			}
		}
		return domain.Threat{}, fmt.Errorf("%s: %w", op, err)
	}

	return toDomain(m), nil
}

func (s *Storage) Update(ctx context.Context, t domain.Threat) (domain.Threat, error) {
	const op = "storage.sqlite.Update"

	m := toModel(t)
	err := s.updateThreatStmt.QueryRowContext(ctx,
		m.Behavior, m.Platform, m.Family, m.FileSize, m.FileType, m.MD5,
	).Scan(
		&m.MD5, &m.Behavior, &m.Platform, &m.Family,
		&m.FileSize, &m.FileType, &m.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.Threat{}, fmt.Errorf("%s: %w", op, storage.ErrThreatNotFound)
		}
		return domain.Threat{}, fmt.Errorf("%s: %w", op, err)
	}

	return toDomain(m), nil
}
