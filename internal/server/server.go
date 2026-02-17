package server

import (
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tdeslauriers/carapace/pkg/config"
	"github.com/tdeslauriers/carapace/pkg/connect"
	exo "github.com/tdeslauriers/carapace/pkg/connect/grpc"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/sign"
	api "github.com/tdeslauriers/silhouette/api/v1"
	"github.com/tdeslauriers/silhouette/internal/address"
	"github.com/tdeslauriers/silhouette/internal/auth"
	"github.com/tdeslauriers/silhouette/internal/definitions"
	"github.com/tdeslauriers/silhouette/internal/phone"
	"github.com/tdeslauriers/silhouette/internal/profile"
	"github.com/tdeslauriers/silhouette/internal/storage"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

type Server interface {
	Run() error
}

func New(cfg *config.Config) (Server, error) {

	// server certs
	serverPki := &connect.Pki{
		CertFile: *cfg.Certs.ServerCert,
		KeyFile:  *cfg.Certs.ServerKey,
		CaFiles:  []string{*cfg.Certs.ServerCa},
	}

	serverTlsConfig, err := connect.NewTlsServerConfig(cfg.Tls, serverPki).Build()
	if err != nil {
		return nil, fmt.Errorf("failed to configure server tls: %v", err)
	}

	// db client certs
	dbClientPki := &connect.Pki{
		CertFile: *cfg.Certs.DbClientCert,
		KeyFile:  *cfg.Certs.DbClientKey,
		CaFiles:  []string{*cfg.Certs.DbCaCert},
	}

	dbClientConfig, err := connect.NewTlsClientConfig(dbClientPki).Build()
	if err != nil {
		return nil, fmt.Errorf("failed to configure database client tls: %v", err)
	}

	// db config
	dbUrl := data.DbUrl{
		Name:     cfg.Database.Name,
		Addr:     cfg.Database.Url,
		Username: cfg.Database.Username,
		Password: cfg.Database.Password,
	}

	db, err := data.NewSqlDbConnector(dbUrl, dbClientConfig).Connect()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %v", err)
	}

	// set up indexer to create blind indexes for encrypted data tables
	indexer := data.NewIndexer([]byte(cfg.Database.IndexSecret))

	// set up field level encryption
	aes, err := base64.StdEncoding.DecodeString(cfg.Database.FieldSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to decode field level encryption key Env var: %v", err)
	}

	cryptor := data.NewServiceAesGcmKey(aes)

	// s2s jwt verifing key
	s2sPublicKey, err := sign.ParsePublicEcdsaCert(cfg.Jwt.S2sVerifyingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse s2s jwt verifying key: %v", err)
	}

	// jwt iamVerifier
	iamPublicKey, err := sign.ParsePublicEcdsaCert(cfg.Jwt.UserVerifyingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse iam verifying public key: %v", err)
	}

	return &server{
		cfg:          cfg,
		serverTls:    serverTlsConfig,
		db:           db,
		addressStore: storage.NewAddressStore(db, indexer, cryptor),
		phoneStore:   storage.NewPhoneStore(db, indexer, cryptor),
		profileStore: storage.NewProfileStore(db, indexer, cryptor),
		xrefStore:    storage.NewXrefStore(db),
		s2sVerifier:  jwt.NewVerifier(cfg.ServiceName, s2sPublicKey),
		iamVerifier:  jwt.NewVerifier(cfg.ServiceName, iamPublicKey),

		logger: slog.Default().
			With(slog.String(definitions.PackageKey, definitions.PackageServer)).
			With(slog.String(definitions.ComponentKey, definitions.ComponentServer)),
	}, nil
}

var _ Server = (*server)(nil)

type server struct {
	cfg          *config.Config
	serverTls    *tls.Config
	db           *sql.DB
	addressStore storage.AddressStore
	phoneStore   storage.PhoneStore
	profileStore storage.ProfileStore
	xrefStore    storage.XrefStore
	s2sVerifier  jwt.Verifier
	iamVerifier  jwt.Verifier

	logger *slog.Logger
}

func (s *server) Run() error {

	// set up tls
	s.serverTls.MinVersion = tls.VersionTLS12
	tlsCreds := credentials.NewTLS(s.serverTls)

	// instantiate auth interceptor
	authInterceptor := auth.NewAuthInterceptor(s.s2sVerifier, s.iamVerifier)

	// isntantiate grpc server
	grpcServer := grpc.NewServer(
		grpc.Creds(tlsCreds),
		grpc.ChainUnaryInterceptor(
			exo.UnaryServerWithTelemetry(s.logger),
			authInterceptor.Unary(),
		),
	)

	// instantiate and register servers with grpc server
	// address server
	api.RegisterAddressesServer(grpcServer, address.NewAddressServer(
		s.addressStore,
		s.profileStore,
		s.xrefStore,
	))

	// phone server
	api.RegisterPhonesServer(grpcServer, phone.NewPhoneServer(
		s.phoneStore,
		s.profileStore,
		s.xrefStore,
	))

	// profile server
	api.RegisterProfilesServer(grpcServer, profile.NewProfileServer(
		s.profileStore,
	))

	// enable grpc reflection if configured
	reflection.Register(grpcServer)

	listener, err := net.Listen("tcp", s.cfg.ServicePort)
	if err != nil {
		s.logger.Error("failed to create listener", "err", err.Error())
		os.Exit(1)
	}

	// start the grpc server
	go func() {
		s.logger.Info(fmt.Sprintf("starting %s gRPC server on port %s", s.cfg.ServiceName, s.cfg.ServicePort))
		if err := grpcServer.Serve(listener); err != nil {
			s.logger.Error(fmt.Sprintf("%s gRPC server failed to start", s.cfg.ServiceName), "err", err.Error())
			os.Exit(1)
		}
	}()

	// wait for interrupt signal for graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	s.logger.Info("shutting down gRPC server...")

	// Graceful stop with timeout
	stopped := make(chan struct{})
	go func() {
		grpcServer.GracefulStop()
		close(stopped)
	}()

	// wait for graceful stop or force stop after timeout
	select {
	case <-stopped:
		s.logger.Info("server stopped gracefully")
	case <-time.After(30 * time.Second):
		s.logger.Warn("forcing server stop after timeout")
		grpcServer.Stop()
	}

	s.logger.Info("closing database connection...")
	if err := s.db.Close(); err != nil {
		s.logger.Error("failed to close database connection", "err", err.Error())
	} else {
		s.logger.Info("database connection closed")
	}

	return nil
}
