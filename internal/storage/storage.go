package storage

import "errors"

var (
	ErrThreatNotFound = errors.New("threat not found")
	ErrThreatExists = errors.New("threat already exists")
)
