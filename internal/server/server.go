package server

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"

	"github.com/tdeslauriers/carapace/pkg/config"
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/silhouette/internal/definitions"
	"github.com/tdeslauriers/silhouette/internal/storage"
)

type Server interface {
	Run() error
}

func New(config *config.Config) (Server, error) {

	// server certs
	serverPki := &connect.Pki{
		CertFile: *config.Certs.ServerCert,
		KeyFile:  *config.Certs.ServerKey,
	}

	serverTlsConfig, err := connect.NewTlsServerConfig(config.Tls, serverPki).Build()
	if err != nil {
		return nil, fmt.Errorf("failed to configure server tls: %v", err)
	}

	// db client certs
	dbClientPki := &connect.Pki{
		CertFile: *config.Certs.DbClientCert,
		KeyFile:  *config.Certs.DbClientKey,
		CaFiles:  []string{*config.Certs.DbCaCert},
	}

	dbClientConfig, err := connect.NewTlsClientConfig(dbClientPki).Build()
	if err != nil {
		return nil, fmt.Errorf("failed to configure database client tls: %v", err)
	}

	// db config
	dbUrl := data.DbUrl{
		Name:     config.Database.Name,
		Addr:     config.Database.Url,
		Username: config.Database.Username,
		Password: config.Database.Password,
	}

	db, err := data.NewSqlDbConnector(dbUrl, dbClientConfig).Connect()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %v", err)
	}

	// set up indexer to create blind indexes for encrypted data tables
	indexer := data.NewIndexer([]byte(config.Database.IndexSecret))

	// set up field level encryption
	aes, err := base64.StdEncoding.DecodeString(config.Database.FieldSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to decode field level encryption key Env var: %v", err)
	}

	cryptor := data.NewServiceAesGcmKey(aes)

	// format public key for use in jwt verification
	pubPem, err := base64.StdEncoding.DecodeString(config.Jwt.UserVerifyingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode user jwt-verifying public key: %v", err)
	}

	pubBlock, _ := pem.Decode(pubPem)
	genericPublicKey, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pub Block to generic public key: %v", err)
	}

	publicKey, ok := genericPublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA public key")
	}

	return &server{
		config:       config,
		serverTls:    serverTlsConfig,
		addressStore: storage.NewAddressStore(db, indexer, cryptor),
		phoneStore:   storage.NewPhoneStore(db, indexer, cryptor),
		profileStore: storage.NewProfileStore(db, indexer, cryptor),
		xrefStore:    storage.NewXrefStore(db),
		verifier:     jwt.NewVerifier(config.ServiceName, publicKey),

		logger: slog.Default().
			With(slog.String(definitions.PackageKey, definitions.PackageServer)).
			With(slog.String(definitions.ComponentKey, definitions.ComponentServer)),
	}, nil
}

type server struct {
	config       *config.Config
	serverTls    *tls.Config
	addressStore storage.AddressStore
	phoneStore   storage.PhoneStore
	profileStore storage.ProfileStore
	xrefStore    storage.XrefStore
	verifier     jwt.Verifier

	logger *slog.Logger
}

func (s *server) Run() error {

	// TODO: impl
	return nil
}
