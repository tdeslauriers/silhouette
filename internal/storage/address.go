package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/silhouette/internal/storage/crypt"
	"github.com/tdeslauriers/silhouette/internal/storage/sql/sqlc"
)

// AddressStore provides persistance operations for addresses
type AddressStore interface {

	// GetAddress retrieves a user's address from the database and decrypts the record.
	GetAddress(ctx context.Context, slug, username string) (*sqlc.Address, error)

	// GetAddressesByUser retrieves all address records for a given user, and decrypts the records.
	GetAddressesByUser(ctx context.Context, username string) ([]*sqlc.Address, error)

	// CountAddresses retrieves a count of how many address records exist for a given user.
	CountAddresses(ctx context.Context, username string) (int64, error)

	// CountPrimaryAddresses retrieves a count of how many primary address records exist for a given user.
	CountPrimaryAddresses(ctx context.Context, username string) (int64, error)

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
func (s *addressStore) GetAddress(ctx context.Context, slug, username string) (*sqlc.Address, error) {

	// get slug index
	slugIndex, err := s.indexer.ObtainBlindIndex(slug)
	if err != nil {
		return nil, err
	}

	// get username index
	userIndex, err := s.indexer.ObtainBlindIndex(username)
	if err != nil {
		return nil, err
	}

	// fetch record from the db
	address, err := s.sql.FindAddressBySlugAndUser(ctx, sqlc.FindAddressBySlugAndUserParams{
		SlugIndex: slugIndex,
		UserIndex: userIndex,
	})
	if err != nil {
		return nil, err
	}

	// decrypt the address record's encrypted fields
	if err := s.cryptor.DecryptAddress(&address); err != nil {
		return nil, err
	}

	return &address, nil
}

// CountAddresses retrieves a count of how many address records exist for a given user.
func (s *addressStore) CountAddresses(ctx context.Context, username string) (int64, error) {

	// get username index
	userIndex, err := s.indexer.ObtainBlindIndex(username)
	if err != nil {
		return 0, err
	}

	// fetch count from the db
	return s.sql.CountAddressesForUser(ctx, userIndex)
}

// CountPrimaryAddresses retrieves a count of how many primary address records exist for a given user.
func (s *addressStore) CountPrimaryAddresses(ctx context.Context, username string) (int64, error) {

	// get username index
	userIndex, err := s.indexer.ObtainBlindIndex(username)
	if err != nil {
		return 0, err
	}

	// fetch count from the db
	return s.sql.CountPrimaryAddressesForUser(ctx, userIndex)
}

// GetAddressesByUser retrieves all address records for a given user, and decrypts the records
func (s *addressStore) GetAddressesByUser(ctx context.Context, username string) ([]*sqlc.Address, error) {

	// get username index
	userIndex, err := s.indexer.ObtainBlindIndex(username)
	if err != nil {
		return nil, err
	}

	// fetch records from the db
	records, err := s.sql.FindAddressesByUser(ctx, userIndex)
	if err != nil {
		return nil, err
	}

	// handle case where no records found
	addresses := make([]*sqlc.Address, 0, len(records))
	if len(records) < 1 {
		return addresses, nil
	}

	// handle single record -> concurrency unnecessary
	if len(records) == 1 {

		// decrypt the address record's encrypted fields
		if err := s.cryptor.DecryptAddress(&records[0]); err != nil {
			return nil, err
		}

		return []*sqlc.Address{&records[0]}, nil
	}

	// handle multiple records -> decrypt concurrently
	var (
		wg          sync.WaitGroup
		addressesCh = make(chan *sqlc.Address, len(records))
		errCh       = make(chan error, len(records))
	)
	for _, record := range records {

		wg.Add(1)

		go func(record sqlc.Address) {
			defer wg.Done()

			// decrypt the address record's encrypted fields
			if err := s.cryptor.DecryptAddress(&record); err != nil {
				errCh <- err
				return
			}

			addressesCh <- &record
		}(record)
	}

	// wait for all decryption goroutines to finish
	wg.Wait()
	close(addressesCh)
	close(errCh)

	// check for errs
	if len(errCh) > 0 {
		var errs []error
		for err := range errCh {
			errs = append(errs, err)
		}
		return nil, fmt.Errorf("failed to decrypt one or more address records: %v", errors.Join(errs...))
	}

	// build slice of decrypted records
	for address := range addressesCh {
		addresses = append(addresses, address)
	}

	return addresses, nil
}

// CreateAddress creates a new address record in the database, encrypting the fields before storage.
func (s *addressStore) CreateAddress(ctx context.Context, address *sqlc.Address) error {

	// if no uuid, create one
	// this should never happen since the service layer should create prior to calling
	if address.Uuid == "" {
		id, err := uuid.NewRandom()
		if err != nil {
			return err
		}
		address.Uuid = id.String()
	}

	// if no slug, create one
	// this should never happen since the service layer should create prior to calling
	if address.Slug == "" {
		slug, err := uuid.NewRandom()
		if err != nil {
			return err
		}
		address.Slug = slug.String()
	}

	// create slug index
	index, err := s.indexer.ObtainBlindIndex(address.Slug)
	if err != nil {
		return err
	}

	// encrypt the address record's fields
	if err := s.cryptor.EncryptAddress(address); err != nil {
		return err
	}

	// store the record in the db
	return s.sql.SaveAddress(ctx, sqlc.SaveAddressParams{
		Uuid:           address.Uuid,
		Slug:           address.Slug,
		SlugIndex:      index,
		StreetAddress:  address.AddressLine1,
		StreetAddress2: address.AddressLine2,
		City:           address.City,
		State:          address.State,
		Zip:            address.Zip,
		Country:        address.Country,
		IsCurrent:      address.IsCurrent,
		IsPrimary:      address.IsPrimary,
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
		IsPrimary:      address.IsPrimary,
		UpdatedAt:      address.UpdatedAt,
		Uuid:           address.Uuid,
	})
}

// DeleteAddress deletes an address record from the database.
func (s *addressStore) DeleteAddress(ctx context.Context, uuid string) error {
	return s.sql.DeleteAddress(ctx, uuid)
}
