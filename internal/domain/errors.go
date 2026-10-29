package domain

import "errors"

var (
	ErrNotFound      = errors.New("threat not found")
	ErrAlreadyExists = errors.New("threat already exists")
	ErrInvalidMD5      = errors.New("invalid md5")
	ErrInvalidName     = errors.New("invalid name")
	ErrInvalidFileSize = errors.New("invalid file size")
)