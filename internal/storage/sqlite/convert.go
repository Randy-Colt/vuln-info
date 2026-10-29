package sqlite

import (
	"database/sql"

	"threat-info/internal/domain"
	"threat-info/internal/storage/models"
)

func toDomain(m models.Threat) domain.Threat {
	var fileType *string
	if m.FileType.Valid {
		fileType = &m.FileType.V
	}

	return domain.Threat{
		MD5:       m.MD5,
		Behavior:  m.Behavior,
		Platform:  m.Platform,
		Family:    m.Family,
		FileSize:  m.FileSize,
		FileType:  fileType,
		CreatedAt: m.CreatedAt,
	}
}

func toModel(t domain.Threat) models.Threat {
	var fileType sql.Null[string]
	if t.FileType != nil {
		fileType = sql.Null[string]{V: *t.FileType, Valid: true}
	}

	return models.Threat{
		MD5:      t.MD5,
		Behavior: t.Behavior,
		Platform: t.Platform,
		Family:   t.Family,
		FileSize: t.FileSize,
		FileType: fileType,
	}
}