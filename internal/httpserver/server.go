package httpserver

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/brian-nunez/ba11y/internal/auth"
	"github.com/brian-nunez/ba11y/internal/authorization"
	"github.com/brian-nunez/ba11y/internal/config"
	v1 "github.com/brian-nunez/ba11y/internal/handlers/v1"
	"github.com/brian-nunez/ba11y/internal/scans"
	"github.com/brian-nunez/ba11y/internal/storage"
	"github.com/labstack/echo/v4"
)

type Server interface {
	Start(addr string) error
	Shutdown(ctx context.Context) error
}

type BootstrapConfig struct {
	StaticDirectories map[string]string
}

type appServer struct {
	echo        *echo.Echo
	db          *sql.DB
	scanService *scans.Service
}

func (s *appServer) Start(addr string) error {
	return s.echo.Start(addr)
}

func (s *appServer) Shutdown(ctx context.Context) error {
	if s.scanService != nil {
		s.scanService.Shutdown()
	}

	if s.db != nil {
		if err := s.db.Close(); err != nil {
			return err
		}
	}

	return s.echo.Shutdown(ctx)
}

func Bootstrap(bootstrapConfig BootstrapConfig) Server {
	appConfig := config.Load()

	db, err := storage.OpenSQLite(appConfig.AppDatabasePath)
	if err != nil {
		panic(fmt.Errorf("open sqlite database: %w", err))
	}

	authService, err := auth.NewService(db)
	if err != nil {
		panic(fmt.Errorf("bootstrap auth service: %w", err))
	}

	scanAuthorizer := authorization.NewScanAuthorizer()
	scanService, err := scans.NewService(scans.Config{
		BBAASBaseURL:       appConfig.BBAASBaseURL,
		BBAASAPIToken:      appConfig.BBAASAPIToken,
		BTickBaseURL:       appConfig.BTickBaseURL,
		BTickAPIKey:        appConfig.BTickAPIKey,
		BTickWebhookURL:    appConfig.BTickWebhookURL,
		BTickWebhookSecret: appConfig.BTickWebhookSecret,
		WorkerConcurrency:  appConfig.WorkerConcurrency,
		WorkerLogPath:      appConfig.WorkerLogPath,
		WorkerDatabasePath: appConfig.WorkerDatabasePath,
	}, scanAuthorizer, db)
	if err != nil {
		panic(fmt.Errorf("bootstrap scan service: %w", err))
	}

	server := New().
		WithStaticAssets(bootstrapConfig.StaticDirectories).
		WithDefaultMiddleware().
		WithErrorHandler().
		WithRoutes(func(e *echo.Echo) {
			v1.RegisterRoutes(e, v1.Dependencies{
				AuthService: authService,
				ScanService: scanService,
			})
		}).
		WithNotFound().
		Build()

	return &appServer{
		echo:        server,
		db:          db,
		scanService: scanService,
	}
}
