package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/silhouette/internal/storage/sql/sqlc"
)

// AddressStore provides persistance operations for addresses
type AddressStore interface {

	// GetAddress retrieves a user's address from the database
	GetAddress(ctx context.Context, username string) (*sqlc.Address, error)
}

// NewAddressStore creates a new instance of AddressStore and
// returns a pointer to an underlying implementation
func NewAddressStore(db *sql.DB, i data.Indexer, c data.Cryptor) AddressStore {

	return &addressStore{
		sql:     sqlc.New(db),
		indexer: i,
		cryptor: c,
	}
}

var _ AddressStore = (*addressStore)(nil)

// addressStore is the concrete implementation of the AddressStore interface, providing
// persistence operations for addresses
type addressStore struct {
	sql     *sqlc.Queries
	indexer data.Indexer
	cryptor data.Cryptor
}

// GetAddress retrieves a user's address from the database, and decyrpts the record
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
		}
	}

	return s.decryptAddress(address)
}

// decryptAddress decrypts the fields of an address record
func (s *addressStore) decryptAddress(address sqlc.Address) (*sqlc.Address, error) {

	var (
		wg sync.WaitGroup

		line1Ch   = make(chan string, 1)
		line2Ch   = make(chan string, 1)
		cityCh    = make(chan string, 1)
		stateCh   = make(chan string, 1)
		zipCh     = make(chan string, 1)
		countryCh = make(chan string, 1)

		errCh = make(chan error, 6)
	)

	if address.AddressLine1.Valid {
		wg.Add(1)
		go s.cryptor.DecryptField(
			"address_line_1",
			address.AddressLine1.String,
			line1Ch,
			errCh,
			&wg,
		)
	} else {
		errCh <- errors.New("address_line_1 field is empty so it cannot be decrypted")
	}

	if address.AddressLine2.Valid {
		wg.Add(1)
		go s.cryptor.DecryptField(
			"address line 2",
			address.AddressLine2.String,
			line2Ch,
			errCh,
			&wg,
		)
	} else {
		line2Ch <- ""
	}

	if address.City.Valid {
		wg.Add(1)
		go s.cryptor.DecryptField(
			"city",
			address.City.String,
			cityCh,
			errCh,
			&wg,
		)
	} else {
		errCh <- errors.New("city field is empty so it cannot be decrypted")
	}

	wg.Add(1)
	go s.cryptor.DecryptField(
		"state",
		address.State.String,
		stateCh,
		errCh,
		&wg,
	)

	if address.State.Valid {
		wg.Add(1)
		go s.cryptor.DecryptField(
			"state",
			address.State.String,
			stateCh,
			errCh,
			&wg,
		)
	} else {
		errCh <- errors.New("state field is empty so it cannot be decrypted")
	}

	if address.Zip.Valid {
		wg.Add(1)
		go s.cryptor.DecryptField(
			"zip",
			address.Zip.String,
			zipCh,
			errCh,
			&wg,
		)
	} else {
		errCh <- errors.New("zip field is empty so it cannot be decrypted")
	}

	if address.Country.Valid {
		wg.Add(1)
		go s.cryptor.DecryptField(
			"country",
			address.Country.String,
			countryCh,
			errCh,
			&wg,
		)
	} else {
		errCh <- errors.New("country field is empty so it cannot be decrypted")
	}

	wg.Wait()
	close(line1Ch)
	close(line2Ch)
	close(cityCh)
	close(stateCh)
	close(zipCh)
	close(countryCh)
	close(errCh)

	if len(errCh) > 0 {
		var errs []error
		for err := range errCh {
			errs = append(errs, err)
		}

		return nil, fmt.Errorf("address record decryption errors: %v", errors.Join(errs...))
	}

	return &sqlc.Address{
		AddressLine1: sql.NullString{String: <-line1Ch, Valid: true},
		AddressLine2: sql.NullString{String: <-line2Ch, Valid: true},
		City:         sql.NullString{String: <-cityCh, Valid: true},
		State:        sql.NullString{String: <-stateCh, Valid: true},
		Zip:          sql.NullString{String: <-zipCh, Valid: true},
		Country:      sql.NullString{String: <-countryCh, Valid: true},
	}, nil
}
