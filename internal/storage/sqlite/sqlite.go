package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
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
            updated_at  TEXT
        );
        CREATE TRIGGER IF NOT EXISTS trg_threat_updated_at
        AFTER UPDATE ON threat
        FOR EACH ROW
        WHEN OLD.updated_at = NEW.updated_at
        BEGIN
            UPDATE threat
            SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE md5 = NEW.md5;
        END;
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
        RETURNING md5, behavior, platform, family, file_size, file_type`)
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


func (s *Storage) Threat(ctx context.Context, md5Hash string) (models.Threat, error) {
    const op = "storage.sqlite.Threat"

	row := s.getThreatStmt.QueryRowContext(ctx, md5Hash)

	var t models.Threat
	err := row.Scan(
		&t.MD5, &t.Behavior, &t.Platform, &t.Family,
		&t.FileSize, &t.FileType, &t.CreatedAt, &t.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.Threat{}, fmt.Errorf("%s: %w", op, storage.ErrThreatNotFound)
		}
		return models.Threat{}, fmt.Errorf("%s: scan: %w", op, err)
	}

	return t, nil
}

func (s *Storage) Create(ctx context.Context, t models.Threat) (models.Threat, error) {
	const op = "storage.sqlite.Create"

	row := s.setThreatStmt.QueryRowContext(ctx,
		t.MD5, t.Behavior, t.Platform, t.Family, t.FileSize, t.FileType,
	)

	var created models.Threat
	err := row.Scan(
		&created.MD5, &created.Behavior, &created.Platform, &created.Family,
		&created.FileSize, &created.FileType, &created.CreatedAt, &created.UpdatedAt,
	)
	if err != nil {
		var sqliteErr sqlite3.Error
		if errors.As(err, &sqliteErr) {
			if sqliteErr.ExtendedCode == sqlite3.ErrConstraintPrimaryKey ||
				sqliteErr.ExtendedCode == sqlite3.ErrConstraintUnique {
				return models.Threat{}, fmt.Errorf("%s: %w", op, storage.ErrThreatExists)
			}
		}
		return models.Threat{}, fmt.Errorf("%s: scan: %w", op, err)
	}

	return created, nil
}

func (s *Storage) Update(ctx context.Context, t models.Threat) (models.Threat, error) {
	const op = "storage.sqlite.Update"

	row := s.updateThreatStmt.QueryRowContext(ctx,
		t.Behavior, t.Platform, t.Family, t.FileSize, t.FileType, t.MD5,
	)

	var updated models.Threat
	err := row.Scan(
		&updated.MD5, &updated.Behavior, &updated.Platform, &updated.Family,
		&updated.FileSize, &updated.FileType, &updated.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.Threat{}, fmt.Errorf("%s: %w", op, storage.ErrThreatNotFound)
		}
		return models.Threat{}, fmt.Errorf("%s: scan: %w", op, err)
	}

	return updated, nil
}
