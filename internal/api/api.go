package api

import (
	"context"
	"errors"
	"fmt"

	"threat-info/internal/domain"
	"threat-info/internal/service"
)

// Server реализует api.StrictServerInterface.
type Server struct {
	svc *service.Threat
}

const (
	NotFoundDetails      = "threat %s not found"
	AlreadyExistsDetails = "threat with hash %s already exists"
	InvalidNameDetails   = "name should be in the format <behavior>.<platform>.<family>"
)

var InternalServerError = errors.New("internal server error")

func New(svc *service.Threat) *Server {
	return &Server{svc: svc}
}

func (s *Server) GetInfoByMd5(ctx context.Context, req GetInfoByMd5RequestObject) (GetInfoByMd5ResponseObject, error) {
	t, err := s.svc.Threat(ctx, req.Md5)
	switch {
	case errors.Is(err, domain.ErrNotFound):
		return GetInfoByMd5404JSONResponse{
			Message: domain.ErrNotFound.Error(),
			Details: new(fmt.Sprintf(NotFoundDetails, req.Md5)),
		}, nil
	case err != nil:
		// return nil, err
		return nil, InternalServerError
	default:
		return GetInfoByMd5200JSONResponse(toThreatResponse(t)), nil
	}
}

func (s *Server) CreateThreat(ctx context.Context, req CreateThreatRequestObject) (CreateThreatResponseObject, error) {
	t, err := s.svc.Create(ctx, service.CreateInput{
		MD5:      req.Body.Md5,
		Name:     req.Body.Name,
		FileSize: req.Body.FileSize,
		FileType: req.Body.FileType,
	})
	switch {
	case errors.Is(err, domain.ErrAlreadyExists):
		return CreateThreat409JSONResponse{
			Message: domain.ErrAlreadyExists.Error(),
			Details: new(fmt.Sprintf(AlreadyExistsDetails, req.Body.Md5)),
		}, nil
	case errors.Is(err, domain.ErrInvalidName):
		return CreateThreat400JSONResponse{
			Message: domain.ErrInvalidName.Error(),
			Details: new(InvalidNameDetails),
		}, nil
	case err != nil:
		return nil, InternalServerError
	default:
		return CreateThreat201JSONResponse{
			Body: toThreatResponse(t),
			Headers: CreateThreat201ResponseHeaders{
				Location: new("/info/" + t.MD5),
			},
		}, nil
	}
}

func (s *Server) UpdateThreat(ctx context.Context, req UpdateThreatRequestObject) (UpdateThreatResponseObject, error) {
	t, err := s.svc.Update(ctx, req.Md5, service.UpdateInput{
		Name:     req.Body.Name,
		FileSize: req.Body.FileSize,
		FileType: req.Body.FileType,
	})
	switch {
	case errors.Is(err, domain.ErrNotFound):
		return UpdateThreat404JSONResponse{
			Message: domain.ErrNotFound.Error(),
			Details: new(fmt.Sprintf(NotFoundDetails, req.Md5)),
		}, nil
	case errors.Is(err, domain.ErrInvalidName):
		return UpdateThreat400JSONResponse{
			Message: domain.ErrInvalidName.Error(),
			Details: new(fmt.Sprintf(AlreadyExistsDetails, req.Md5)),
		}, nil
	case err != nil:
		return nil, InternalServerError
	}
	return UpdateThreat200JSONResponse(toThreatResponse(t)), nil
}

func toThreatResponse(t domain.Threat) ThreatResponse {
	return ThreatResponse{
		Md5:       t.MD5,
		Name:      t.Behavior + "." + t.Platform + "." + t.Family,
		FileSize:  t.FileSize,
		FileType:  t.FileType,
		CreatedAt: t.CreatedAt,
	}
}
