package address

import (
	"log/slog"

	"github.com/tdeslauriers/carapace/pkg/validate"
	api "github.com/tdeslauriers/silhouette/api/v1"
	"github.com/tdeslauriers/silhouette/internal/definitions"
	"github.com/tdeslauriers/silhouette/internal/storage"
)

// addressServer is the gRPC server implementaiton for the Address service
type addressServer struct {
	addressStore storage.AddressStore
	profileStore storage.ProfileStore
	xrefStore    storage.XrefStore

	logger *slog.Logger

	api.UnimplementedAddressesServer
}

// NewAddressServer creates a new instance of the gRPC Address server, returning a pointer to a concrete
// implementaiton of the AddressesServer interface
func NewAddressServer(
	addressSql storage.AddressStore,
	profileSql storage.ProfileStore,
	xrefSql storage.XrefStore,
) api.AddressesServer {

	return &addressServer{
		addressStore: addressSql,
		profileStore: profileSql,
		xrefStore:    xrefSql,

		logger: slog.Default().
			With(slog.String(definitions.ComponentKey, definitions.ComponentAddressServer)).
			With(slog.String(definitions.PackageKey, definitions.PackageAddress)),
	}
}

// AddressUpsert provides functions to access data in an address record creation or update operations request models
type AddressUpsert interface {
	GetStreetAddress() string
	GetStreetAddress_2() string
	GetCity() string
	GetStateProvince() string
	GetPostalCode() string
	GetCountry() string
	GetUsername() string
}

// ValidateCmd validates the fields of an AddressUpsert request model
func ValidateCmd(cmd AddressUpsert) error {

	// validate email
	if err := validate.IsValidEmail(cmd.GetUsername()); err != nil {
		return err
	}

	// validate address line 1
	if err := validate.ValidateStreetAddress(cmd.GetStreetAddress()); err != nil {
		return err
	}

	// validate address line 2, if present
	if len(cmd.GetStreetAddress_2()) > 0 {
		if err := validate.ValidateStreetAddress(cmd.GetStreetAddress_2()); err != nil {
			return err
		}
	}

	// validate city
	if err := validate.ValidateCity(cmd.GetCity()); err != nil {
		return err
	}

	// validate state
	if err := validate.ValidateState(cmd.GetStateProvince()); err != nil {
		return err
	}

	// validate postal code
	if err := validate.ValidateZipCode(cmd.GetPostalCode()); err != nil {
		return err
	}

	// validate country
	if err := validate.ValidateCountry(cmd.GetCountry()); err != nil {
		return err
	}

	return nil
}
