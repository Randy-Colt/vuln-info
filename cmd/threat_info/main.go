package main

import (
	"context"
	"errors"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"threat-info/internal/api"
	"threat-info/internal/config"
	"threat-info/internal/lib/middleware"
	"threat-info/internal/service"
	"threat-info/internal/storage/sqlite"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/httprate"
	"github.com/swaggest/swgui/v5emb"
)

func main() {
	cfg := config.MustLoad()

	logger := setupLogger(cfg.LogLevel)
	logger.Debug("logger debug mode enabled")

	logger.Info("initializing database")
	repo, err := sqlite.New("threats.db")
	if err != nil {
		log.Fatal(err)
	}
	defer repo.Close()

	logger.Info("initializing server", slog.String("address", cfg.Address))
	svc := service.New(repo, logger)

	srv := api.New(svc)

	swagger, err := api.GetSpec()
	if err != nil {
		log.Fatal(err)
	}

	r := chi.NewRouter()

	// rate limiter
	r.Use(httprate.LimitBy(
		cfg.RequestLimit,
		time.Minute,
		func(r *http.Request) (string, error) {
        	return httprate.CanonicalizeIP(r.RemoteAddr), nil
		},
		httprate.WithLimitHandler(
			http.HandlerFunc(middleware.FormateRateLimit),
		),
	))

	r.Get("/openapi.json", api.ServeOpenAPI)
	r.Mount("/docs", v5emb.New(
		"Threat Info API",
		"/openapi.json",
		"/docs/",
	))

	r.Group(func(apiRouter chi.Router) {
		apiRouter.Use(middleware.Validator(swagger)) 

		strictHandler := api.NewStrictHandler(srv, nil)
		apiRouter.Mount("/", api.Handler(strictHandler))
	})

	httpServer := &http.Server{
		Addr:    cfg.Address,
		Handler: r,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening on " + cfg.Address)
		if err := httpServer.ListenAndServeTLS("certs/cert.pem", "certs/key.pem"); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		log.Fatal("server failed: " + err.Error())
	case sig := <-stop:
		logger.Info("shutdown signal received", slog.String("signal", sig.String()))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10 * time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		logger.Error("graceful shutdown failed", slog.Any("error", err))
	} else {
		logger.Info("server stopped")
	}
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
