package sqlite

import (
	"database/sql"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
)


type Storage struct {
    db *sql.DB
}


func New(storagePath string) (*Storage, error) {
    const op = "storage.sqlite.NewStorage"

    db, err := sql.Open("sqlite3", storagePath)
    if err != nil {
        return nil, fmt.Errorf("%s: %w", op, err)
    }

    stmt, err := db.Prepare(`
        CREATE TABLE IF NOT EXISTS threat(
            hash TEXT UNIQUE NOT NULL,
            behavior TEXT NOT NULL,
            platform TEXT NOT NULL,
            family TEXT NOT NULL,
            created_at TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            file_type TEXT DEFAULT undefined,
            file_path TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS  ON threat();
    `)
    if err != nil {
        return nil, fmt.Errorf("%s: %w", op, err)
    }

    _, err = stmt.Exec()
    if err != nil {
        return nil, fmt.Errorf("%s: %w", op, err)
    }

    return &Storage{db: db}, nil
}


func GetThreat(md5Hash string) (string, error) {
	
}
