package main

import (
	"log/slog"
	"os"
	"strings"
	"threat-info/internal/config"
)

func main() {
	cfg := config.MustLoad()

	logger := setupLogger(cfg.LogLevel)

	logger.Info("initializing server", slog.String("address", cfg.Address)) // Помимо сообщения выведем параметр с адресом
	logger.Debug("logger debug mode enabled")
}

func setupLogger(level string) *slog.Logger {
	var logLevel slog.Level

	switch strings.ToUpper(level) {
	case "DEBUG":
		logLevel = slog.LevelDebug
	default:
		logLevel = slog.LevelInfo
	}

	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
}
