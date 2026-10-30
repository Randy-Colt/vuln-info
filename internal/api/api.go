package api

import (
	"context"
	"errors"

	"threat-info/internal/domain"
	"threat-info/internal/service"
)

// Server реализует api.StrictServerInterface.
// Имя отличается от сгенерированного Handler, чтобы не было коллизии.
type Server struct {
	svc *service.Threat
}

func New(svc *service.Threat) *Server {
	return &Server{svc: svc}
}

func (h *Server) GetInfoByMd5(ctx context.Context, req GetInfoByMd5RequestObject) (GetInfoByMd5ResponseObject, error) {
	t, err := h.svc.Threat(ctx, req.Md5)
	if err != nil {
		return nil, mapDomainError(err)
	}
	return GetInfoByMd5200JSONResponse(toThreatResponse(t)), nil
}

func (h *Server) CreateThreat(ctx context.Context, req CreateThreatRequestObject) (CreateThreatResponseObject, error) {
	t, err := h.svc.Create(ctx, service.CreateInput{
		MD5:      req.Body.Md5,
		Name:     req.Body.Name,
		FileSize: req.Body.FileSize,
		FileType: &req.Body.FileType,
	})
	if err != nil {
		return nil, mapDomainError(err)
	}
	return CreateThreat201JSONResponse{
		Body: toThreatResponse(t),
		Headers: CreateThreat201ResponseHeaders{
			Location: "/info/" + t.MD5,
		},
	}, nil
}

func (h *Server) UpdateThreat(ctx context.Context, req UpdateThreatRequestObject) (UpdateThreatResponseObject, error) {
	t, err := h.svc.Update(ctx, req.Md5, service.UpdateInput{
		Name:     req.Body.Name,
		FileSize: req.Body.FileSize,
		FileType: &req.Body.FileType,
	})
	if err != nil {
		return nil, mapDomainError(err)
	}
	return UpdateThreat200JSONResponse(toThreatResponse(t)), nil
}

func toThreatResponse(t domain.Threat) ThreatResponse {
	return ThreatResponse{
		Md5:       t.MD5,
		Name:      t.Behavior + "." + t.Platform + "." + t.Family,
		FileSize:  t.FileSize,
		FileType:  *t.FileType,
		CreatedAt: t.CreatedAt,
	}
}

// TODO исправить
// mapDomainError превращает доменные ошибки в сгенерированные ответы.
// Если ошибка не доменная, strict-server сам вернёт 500.
func mapDomainError(err error) error {
	switch {
	case errors.Is(err, domain.ErrNotFound):
		return &ErrorResponse{Message: "threat not found"} // пример
	default:
		return err
	}
}