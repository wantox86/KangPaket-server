package main

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/wantox86/KangPaket-server/internal/auth"
	"github.com/wantox86/KangPaket-server/internal/config"
	"github.com/wantox86/KangPaket-server/internal/db"
	"github.com/wantox86/KangPaket-server/internal/httpapi"
	"github.com/wantox86/KangPaket-server/internal/migrate"
	"github.com/wantox86/KangPaket-server/internal/syncstore"
	"github.com/wantox86/KangPaket-server/migrations"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	var err error
	if len(os.Args) > 1 {
		err = runCLI(os.Args[1], os.Args[2:])
	} else {
		err = run(log)
	}
	if err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func newAuthService(cfg *config.Config, conn *sql.DB, log *slog.Logger) (*auth.Service, error) {
	hasher, err := auth.DefaultHasher()
	if err != nil {
		return nil, err
	}
	return &auth.Service{
		Store:      auth.NewMySQLStore(conn),
		Hasher:     hasher,
		Secret:     []byte(cfg.JWTSecret),
		AccessTTL:  cfg.AccessTokenTTL,
		RefreshTTL: cfg.RefreshTokenTTL,
		Log:        log,
	}, nil
}

func purgeExpired(ctx context.Context, store auth.Store) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			store.PurgeExpired(ctx, time.Now().Add(-7*24*time.Hour))
		}
	}
}

func run(log *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	conn, err := db.Open(ctx, cfg.DSN())
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := migrate.Up(ctx, conn, migrations.FS, log); err != nil {
		return err
	}

	svc, err := newAuthService(cfg, conn, log)
	if err != nil {
		return err
	}
	go purgeExpired(ctx, svc.Store)

	srv := &http.Server{
		Addr: ":" + cfg.Port,
		Handler: httpapi.NewRouter(httpapi.Options{
			DB:                  conn,
			Log:                 log,
			Auth:                svc,
			Sync:                syncstore.NewMySQLStore(conn),
			RegistrationEnabled: cfg.RegistrationEnabled,
			TrustProxyHeaders:   cfg.TrustProxyHeaders,
			CORSAllowedOrigins:  cfg.CORSAllowedOrigins,
			RateLimitPerMin:     cfg.RateLimitPerMin,
			RateLimitUserPerMin: cfg.RateLimitUserPerMin,
		}),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	log.Info("server listening", "addr", srv.Addr, "registration_enabled", cfg.RegistrationEnabled)

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	log.Info("shutting down")
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
