package storage

import "errors"

var (
	ErrVulnNotFound = errors.New("threat not found")
	ErrVulnExists = errors.New("threat already exists")
)
