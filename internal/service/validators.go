package service

import (
	"encoding/hex"
	"strings"
	"threat-info/internal/domain"
)

func normalizeMD5(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// validateMD5 возвращает domain.ErrInvalidMD5.
func validateMD5(s string) error {
	if len(s) != 32 {
		return domain.ErrInvalidMD5
	}
	if _, err := hex.DecodeString(s); err != nil {
		return domain.ErrInvalidMD5
	}
	return nil
}

func normalizeFileType(s *string) *string {
	if s == nil {
		return nil
	}
	v := strings.TrimSpace(*s)
	if v == "" {
		return nil
	}
	return &v
}

// parseName разбирает <behavior>.<platform>.<family>.
// Всё после третьей точки остаётся в family, чтобы обратная сборка
// behavior + "." + platform + "." + family возвращала исходное имя.
func parseName(name string) (behavior, platform, family string, err error) {
	parts := strings.SplitN(strings.TrimSpace(name), ".", 3)
	if len(parts) < 3 {
		return "", "", "", domain.ErrInvalidName
	}
	for i, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			return "", "", "", domain.ErrInvalidName
		}
		parts[i] = p
	}
	return parts[0], parts[1], parts[2], nil
}