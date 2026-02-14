package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/tdeslauriers/carapace/pkg/config"
	"github.com/tdeslauriers/silhouette/internal/definitions"
	"github.com/tdeslauriers/silhouette/internal/server"
)

func main() {

	// set logging to json format for application
	jsonHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	slog.SetDefault(slog.New(jsonHandler).
		With(slog.String(definitions.ServiceKey, definitions.ServiceProfile)))

	// create a logger for the main package
	logger := slog.Default().
		With(slog.String(definitions.PackageKey, definitions.PackageMain)).
		With(slog.String(definitions.ComponentKey, definitions.ComponentMain))

	// service definition and requirements
	def := config.SvcDefinition{
		ServiceName: "silhouette",
		Tls:         config.MutualTls,
		Requires: config.Requires{
			Db:               true,
			IndexSecret:      true,
			AesSecret:        true,
			S2sVerifyingKey:  true,
			UserVerifyingKey: true,
		},
	}

	// load configuration and environment variables
	config, err := config.Load(def)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to load %s profile service configuration", def.ServiceName), "err", err.Error())
		os.Exit(1)
	}

	// create the server
	srv, err := server.New(config)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to create %s profile service server", def.ServiceName), "err", err.Error())
		os.Exit(1)
	}

	// run the server
	if err := srv.Run(); err != nil {
		logger.Error(fmt.Sprintf("failed to run %s profile service server", def.ServiceName), "err", err.Error())
		os.Exit(1)
	}
}
