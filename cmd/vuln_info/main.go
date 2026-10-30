package main

import (
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"threat-info/internal/api"
	"threat-info/internal/config"
	"threat-info/internal/storage/sqlite"
	"threat-info/internal/service"
	
	"github.com/go-chi/chi/v5"
	"github.com/oapi-codegen/nethttp-middleware"
)

func main() {
	cfg := config.MustLoad()

	logger := setupLogger(cfg.LogLevel)

	logger.Info("initializing database")
	repo, err := sqlite.New("threats.db")
	if err != nil {
		log.Fatal(err)
	}
	defer repo.Close()

	logger.Info("initializing server", slog.String("address", cfg.Address))
	svc := service.New(repo)
	srv := api.New(svc)

	swagger, err := api.GetSwagger()
	if err != nil {
		log.Fatal(err)
	}

	// Валидация path-параметров (включая md5 по pattern) и тела запроса.
	validator := nethttpmiddleware.OapiRequestValidator(swagger)

	r := chi.NewRouter()
	r.Use(validator)

	strictHandler := api.NewStrictHandler(srv, nil)
	r.Mount("/", api.Handler(strictHandler))

	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
	
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
