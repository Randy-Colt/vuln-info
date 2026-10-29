package service

import (
	"context"
	"errors"
	"fmt"

	"threat-info/internal/domain"
	"threat-info/internal/storage"
)

type ThreatRepository interface {
	Threat(ctx context.Context, md5 string) (domain.Threat, error)
	Create(ctx context.Context, t domain.Threat) (domain.Threat, error)
	Update(ctx context.Context, t domain.Threat) (domain.Threat, error)
}

type ThreatService struct {
	repo ThreatRepository
}

func NewThreatService(repo ThreatRepository) *ThreatService {
	return &ThreatService{repo: repo}
}

type CreateInput struct {
	MD5      string
	Name     string
	FileSize int64
	FileType *string
}

type UpdateInput struct {
	Name     string
	FileSize int64
	FileType *string
}

func (s *ThreatService) Threat(ctx context.Context, md5 string) (domain.Threat, error) {
	const op = "service.ThreatService.Threat"

	md5 = normalizeMD5(md5)
	if err := validateMD5(md5); err != nil {
		return domain.Threat{}, fmt.Errorf("%s: %w", op, err) // domain.ErrInvalidMD5
	}

	t, err := s.repo.Threat(ctx, md5)
	if errors.Is(err, storage.ErrThreatNotFound) {
		return domain.Threat{}, fmt.Errorf("%s: %w", op, domain.ErrNotFound)
	}
	if err != nil {
		return domain.Threat{}, fmt.Errorf("%s: %w", op, err)
	}
	return t, nil
}

func (s *ThreatService) Create(ctx context.Context, in CreateInput) (domain.Threat, error) {
	const op = "service.ThreatService.Create"

	md5 := normalizeMD5(in.MD5)
	if err := validateMD5(md5); err != nil {
		return domain.Threat{}, fmt.Errorf("%s: %w", op, err)
	}

	behavior, platform, family, err := parseName(in.Name)
	if err != nil {
		return domain.Threat{}, fmt.Errorf("%s: %w", op, err) // domain.ErrInvalidName
	}

	if in.FileSize < 0 {
		return domain.Threat{}, fmt.Errorf("%s: %w", op, domain.ErrInvalidFileSize)
	}

	t := domain.Threat{
		MD5:      md5,
		Behavior: behavior,
		Platform: platform,
		Family:   family,
		FileSize: in.FileSize,
		FileType: normalizeFileType(in.FileType),
	}

	created, err := s.repo.Create(ctx, t)
	if errors.Is(err, storage.ErrThreatExists) {
		return domain.Threat{}, fmt.Errorf("%s: %w", op, domain.ErrAlreadyExists)
	}
	if err != nil {
		return domain.Threat{}, fmt.Errorf("%s: %w", op, err)
	}
	return created, nil
}

func (s *ThreatService) Update(ctx context.Context, md5 string, in UpdateInput) (domain.Threat, error) {
	const op = "service.ThreatService.Update"

	md5 = normalizeMD5(md5)
	if err := validateMD5(md5); err != nil {
		return domain.Threat{}, fmt.Errorf("%s: %w", op, err)
	}

	behavior, platform, family, err := parseName(in.Name)
	if err != nil {
		return domain.Threat{}, fmt.Errorf("%s: %w", op, err)
	}

	if in.FileSize < 0 {
		return domain.Threat{}, fmt.Errorf("%s: %w", op, domain.ErrInvalidFileSize)
	}

	t := domain.Threat{
		MD5:      md5,
		Behavior: behavior,
		Platform: platform,
		Family:   family,
		FileSize: in.FileSize,
		FileType: normalizeFileType(in.FileType),
	}

	updated, err := s.repo.Update(ctx, t)
	if errors.Is(err, storage.ErrThreatNotFound) {
		return domain.Threat{}, fmt.Errorf("%s: %w", op, domain.ErrNotFound)
	}
	if err != nil {
		return domain.Threat{}, fmt.Errorf("%s: %w", op, err)
	}
	return updated, nil
}