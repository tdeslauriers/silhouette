package storage

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/silhouette/internal/storage/crypt"
	"github.com/tdeslauriers/silhouette/internal/storage/sql/sqlc"
)

// AddressStore provides persistance operations for addresses
type AddressStore interface {

	// GetAddress retrieves a user's address from the database and decrypts the record.
	GetAddress(ctx context.Context, username string) (*sqlc.Address, error)

	// CreateAddress creates a new address record in the database, encrypting the fields before storage.
	CreateAddress(ctx context.Context, address *sqlc.Address) error

	// UpdateAddress updates an existing address record in the database, encrypting the fields before storage.
	UpdateAddress(ctx context.Context, address *sqlc.Address) error

	// DeleteAddress deletes an address record from the database.
	DeleteAddress(ctx context.Context, uuid string) error
}

// NewAddressStore creates a new instance of AddressStore and
// returns a pointer to an underlying implementation
func NewAddressStore(db *sql.DB, i data.Indexer, c data.Cryptor) AddressStore {

	return &addressStore{
		sql:     sqlc.New(db),
		indexer: i,
		cryptor: crypt.NewAddressCryptor(c),
	}
}

var _ AddressStore = (*addressStore)(nil)

// addressStore is the concrete implementation of the AddressStore interface, providing
// persistence operations for addresses
type addressStore struct {
	sql     *sqlc.Queries
	indexer data.Indexer
	cryptor crypt.AddressCryptor
}

// GetAddress retrieves a user's address from the database, and decrypts the record
func (s *addressStore) GetAddress(ctx context.Context, username string) (*sqlc.Address, error) {

	// get username index
	index, err := s.indexer.ObtainBlindIndex(username)
	if err != nil {
		return nil, err
	}

	// fetch record from the db
	address, err := s.sql.FindAddressByUserIndex(ctx, index)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("address not found for user %s", username)
		} else {
			return nil, err
		}
	}

	// decrypt the address record's encrypted fields
	if err := s.cryptor.DecryptAddress(&address); err != nil {
		return nil, err
	}

	return &address, nil
}

// CreateAddress creates a new address record in the database, encrypting the fields before storage.
func (s *addressStore) CreateAddress(ctx context.Context, address *sqlc.Address) error {

	// encrypt the address record's fields
	if err := s.cryptor.EncryptAddress(address); err != nil {
		return err
	}

	// store the record in the db
	return s.sql.SaveAddress(ctx, sqlc.SaveAddressParams{
		Uuid:           address.Uuid,
		StreetAddress:  address.AddressLine1,
		StreetAddress2: address.AddressLine2,
		City:           address.City,
		State:          address.State,
		Zip:            address.Zip,
		Country:        address.Country,
		IsCurrent:      address.IsCurrent,
		UpdatedAt:      address.UpdatedAt,
		CreatedAt:      address.CreatedAt,
	})
}

// UpdateAddress updates an existing address record in the database, encrypting the fields before storage.
func (s *addressStore) UpdateAddress(ctx context.Context, address *sqlc.Address) error {

	// encrypt the address record's fields
	if err := s.cryptor.EncryptAddress(address); err != nil {
		return err
	}

	// update the record in the db
	return s.sql.UpdateAddress(ctx, sqlc.UpdateAddressParams{
		StreetAddress:  address.AddressLine1,
		StreetAddress2: address.AddressLine2,
		City:           address.City,
		State:          address.State,
		Zip:            address.Zip,
		Country:        address.Country,
		IsCurrent:      address.IsCurrent,
		UpdatedAt:      address.UpdatedAt,
		Uuid:           address.Uuid,
	})
}

// DeleteAddress deletes an address record from the database.
func (s *addressStore) DeleteAddress(ctx context.Context, uuid string) error {
	return s.sql.DeleteAddress(ctx, uuid)
}
