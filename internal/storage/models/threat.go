package models

import (
	"database/sql"
	"time"
)


type Threat struct {
	MD5      string
	Behavior  string
	Platform  string
	Family    string
	FileSize  int64
	FileType  sql.Null[string]
	CreatedAt time.Time
}