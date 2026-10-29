package domain

import "time"

type Threat struct {
	MD5       string
	Behavior  string
	Platform  string
	Family    string
	FileSize  int64
	FileType  *string
	CreatedAt time.Time
}