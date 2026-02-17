package crypt

import (
	"database/sql"
	"errors"
	"fmt"
	"sync"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/silhouette/internal/storage/sql/sqlc"
)

// AddressCryptor provides encryption and decryption operations for address records
type AddressCryptor interface {

	// EncryptAddress encrypts the fields of an address record
	EncryptAddress(address *sqlc.Address) error

	// DecryptAddress decrypts the fields of an address record
	DecryptAddress(address *sqlc.Address) error
}

// NewAddressCryptor creates a new instance of the AddressCryptor interface, returning
// a pointer to an underlying implementation.
func NewAddressCryptor(c data.Cryptor) AddressCryptor {
	return &addressCryptor{
		cryptor: c,
	}
}

var _ AddressCryptor = (*addressCryptor)(nil)

// addressCryptor is the concrete implementation of the AddressCryptor interface, providing
// encryption and decryption operations for address records
type addressCryptor struct {
	cryptor data.Cryptor
}

// EncryptAddress encrypts the fields of an address record
func (ac *addressCryptor) EncryptAddress(address *sqlc.Address) error {

	var (
		wg sync.WaitGroup

		slugCh    = make(chan string, 1)
		line1Ch   = make(chan string, 1)
		line2Ch   = make(chan string, 1)
		cityCh    = make(chan string, 1)
		stateCh   = make(chan string, 1)
		zipCh     = make(chan string, 1)
		countryCh = make(chan string, 1)

		errCh = make(chan error, 7)
	)

	if address.Slug != "" {
		wg.Add(1)
		go ac.cryptor.EncryptField(
			"slug",
			address.Slug,
			slugCh,
			errCh,
			&wg,
		)
	} else {
		errCh <- errors.New("slug field is empty so it cannot be encrypted")
	}

	if address.AddressLine1.Valid {

		wg.Add(1)
		go ac.cryptor.EncryptField(
			"address_line_1",
			address.AddressLine1.String,
			line1Ch,
			errCh,
			&wg,
		)
	} else {
		errCh <- errors.New("address_line_1 field is empty so it cannot be encrypted")
	}

	if address.AddressLine2.Valid && len(address.AddressLine2.String) > 0 {
		wg.Add(1)
		go ac.cryptor.EncryptField(
			"address_line_2",
			address.AddressLine2.String,
			line2Ch,
			errCh,
			&wg,
		)
	}

	if address.City.Valid {
		wg.Add(1)
		go ac.cryptor.EncryptField(
			"city",
			address.City.String,
			cityCh,
			errCh,
			&wg,
		)
	} else {
		errCh <- errors.New("city field is empty so it cannot be encrypted")
	}

	if address.State.Valid {
		wg.Add(1)
		go ac.cryptor.EncryptField(
			"state",
			address.State.String,
			stateCh,
			errCh,
			&wg,
		)
	} else {
		errCh <- errors.New("state field is empty so it cannot be encrypted")
	}

	if address.Zip.Valid {
		wg.Add(1)
		go ac.cryptor.EncryptField(
			"zip",
			address.Zip.String,
			zipCh,
			errCh,
			&wg,
		)
	} else {
		errCh <- errors.New("zip field is empty so it cannot be encrypted")
	}

	if address.Country.Valid {
		wg.Add(1)
		go ac.cryptor.EncryptField(
			"country",
			address.Country.String,
			countryCh,
			errCh,
			&wg,
		)
	} else {
		errCh <- errors.New("country field is empty so it cannot be encrypted")
	}

	wg.Wait()
	close(slugCh)
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

		return fmt.Errorf("address record encryption errors: %v", errors.Join(errs...))
	}

	address.Slug = <-slugCh
	address.AddressLine1 = sql.NullString{String: <-line1Ch, Valid: true}

	line2, ok := <-line2Ch
	if ok {
		address.AddressLine2 = sql.NullString{String: line2, Valid: true}
	} else {
		address.AddressLine2 = sql.NullString{String: "", Valid: false}
	}

	address.City = sql.NullString{String: <-cityCh, Valid: true}
	address.State = sql.NullString{String: <-stateCh, Valid: true}
	address.Zip = sql.NullString{String: <-zipCh, Valid: true}
	address.Country = sql.NullString{String: <-countryCh, Valid: true}

	return nil
}

// DecryptAddress decrypts the fields of an address record
func (ac *addressCryptor) DecryptAddress(address *sqlc.Address) error {

	var (
		wg sync.WaitGroup

		slugCh    = make(chan string, 1)
		line1Ch   = make(chan string, 1)
		line2Ch   = make(chan string, 1)
		cityCh    = make(chan string, 1)
		stateCh   = make(chan string, 1)
		zipCh     = make(chan string, 1)
		countryCh = make(chan string, 1)

		errCh = make(chan error, 7)
	)

	if address.Slug != "" {
		wg.Add(1)
		go ac.cryptor.DecryptField(
			"slug",
			address.Slug,
			slugCh,
			errCh,
			&wg,
		)
	} else {
		errCh <- errors.New("slug field is empty so it cannot be decrypted")
	}

	if address.AddressLine1.Valid {
		wg.Add(1)
		go ac.cryptor.DecryptField(
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
		go ac.cryptor.DecryptField(
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
		go ac.cryptor.DecryptField(
			"city",
			address.City.String,
			cityCh,
			errCh,
			&wg,
		)
	} else {
		errCh <- errors.New("city field is empty so it cannot be decrypted")
	}

	if address.State.Valid {
		wg.Add(1)
		go ac.cryptor.DecryptField(
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
		go ac.cryptor.DecryptField(
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
		go ac.cryptor.DecryptField(
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
	close(slugCh)
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

		return fmt.Errorf("address record decryption errors: %v", errors.Join(errs...))
	}

	address.Slug = <-slugCh
	address.AddressLine1 = sql.NullString{String: <-line1Ch, Valid: true}

	line2, ok := <-line2Ch
	if ok {
		address.AddressLine2 = sql.NullString{String: line2, Valid: true}
	} else {
		address.AddressLine2 = sql.NullString{String: "", Valid: false}
	}

	address.City = sql.NullString{String: <-cityCh, Valid: true}
	address.State = sql.NullString{String: <-stateCh, Valid: true}
	address.Zip = sql.NullString{String: <-zipCh, Valid: true}
	address.Country = sql.NullString{String: <-countryCh, Valid: true}

	return nil
}
