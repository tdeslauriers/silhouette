package crypt

import (
	"database/sql"
	"errors"
	"fmt"
	"sync"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/silhouette/internal/storage/sql/sqlc"
)

// PhoneCryptor provides encryption and decryption operations for phone numbers
type PhoneCryptor interface {

	// EncryptPhone encrypts the fields of a phone record before storage.
	EncryptPhone(phone *sqlc.Phone) error

	// DecryptPhone decrypts the fields of a phone record after retrieval.
	DecryptPhone(phone *sqlc.Phone) error
}

// NewPhoneCryptor creates a new instance of PhoneCryptor
func NewPhoneCryptor(c data.Cryptor) PhoneCryptor {
	return &phoneCryptor{
		cryptor: c,
	}
}

// phoneCryptor is the concrete implementation of the PhoneCryptor interface,
// providing encryption and decryption operations for phone numbers
type phoneCryptor struct {
	cryptor data.Cryptor
}

// EncryptPhone encrypts the fields of a phone record before storage.
func (pc *phoneCryptor) EncryptPhone(phone *sqlc.Phone) error {

	var (
		wg sync.WaitGroup

		countryCodeCh = make(chan string, 1)
		phNumberCh    = make(chan string, 1)
		extCh         = make(chan string, 1)
		phTypeCh      = make(chan string, 1)

		errCh = make(chan error, 4)
	)

	if phone.CountryCode.Valid {
		wg.Add(1)
		go pc.cryptor.EncryptField(
			"country_code",
			phone.CountryCode.String,
			countryCodeCh,
			errCh,
			&wg,
		)
	} else {
		countryCodeCh <- ""
	}

	if phone.PhoneNumber.Valid {
		wg.Add(1)
		go pc.cryptor.EncryptField(
			"phone_number",
			phone.PhoneNumber.String,
			phNumberCh,
			errCh,
			&wg,
		)
	} else {
		errCh <- errors.New("phone_number field is empty so it cannot be encrypted")
	}

	if phone.Extension.Valid {
		wg.Add(1)
		go pc.cryptor.EncryptField(
			"extension",
			phone.Extension.String,
			extCh,
			errCh,
			&wg,
		)
	} else {
		extCh <- ""
	}

	if phone.PhoneType.Valid {
		wg.Add(1)
		go pc.cryptor.EncryptField(
			"type",
			phone.PhoneType.String,
			phTypeCh,
			errCh,
			&wg,
		)
	} else {
		errCh <- errors.New("phone_type field is empty so it cannot be encrypted")
	}

	wg.Wait()
	close(countryCodeCh)
	close(phNumberCh)
	close(extCh)
	close(phTypeCh)
	close(errCh)

	if len(errCh) > 0 {
		var errs []error
		for err := range errCh {
			errs = append(errs, err)
		}

		return fmt.Errorf("phone record encryption errors: %v", errors.Join(errs...))
	}

	phone.CountryCode = sql.NullString{String: <-countryCodeCh, Valid: true}
	phone.PhoneNumber = sql.NullString{String: <-phNumberCh, Valid: true}
	phone.Extension = sql.NullString{String: <-extCh, Valid: true}
	phone.PhoneType = sql.NullString{String: <-phTypeCh, Valid: true}

	return nil
}

// DecryptPhone decrypts the fields of a phone record after retrieval.
func (pc *phoneCryptor) DecryptPhone(phone *sqlc.Phone) error {

	var (
		wg sync.WaitGroup

		countryCodeCh = make(chan string, 1)
		phNumberCh    = make(chan string, 1)
		extCh         = make(chan string, 1)
		phTypeCh      = make(chan string, 1)

		errCh = make(chan error, 4)
	)

	if phone.CountryCode.Valid {
		wg.Add(1)
		go pc.cryptor.DecryptField(
			"country_code",
			phone.CountryCode.String,
			countryCodeCh,
			errCh,
			&wg,
		)
	} else {
		errCh <- errors.New("country_code field is empty so it cannot be decrypted")
	}

	if phone.PhoneNumber.Valid {
		wg.Add(1)
		go pc.cryptor.DecryptField(
			"phone_number",
			phone.PhoneNumber.String,
			phNumberCh,
			errCh,
			&wg,
		)
	} else {
		errCh <- errors.New("phone_number field is empty so it cannot be decrypted")
	}

	if phone.Extension.Valid {
		wg.Add(1)
		go pc.cryptor.DecryptField(
			"extension",
			phone.Extension.String,
			extCh,
			errCh,
			&wg,
		)
	} else {
		extCh <- ""
	}

	if phone.PhoneType.Valid {
		wg.Add(1)
		go pc.cryptor.DecryptField(
			"type",
			phone.PhoneType.String,
			phTypeCh,
			errCh,
			&wg,
		)
	} else {
		errCh <- errors.New("phone_type field is empty so it cannot be decrypted")
	}

	wg.Wait()
	close(countryCodeCh)
	close(phNumberCh)
	close(extCh)
	close(phTypeCh)
	close(errCh)

	if len(errCh) > 0 {
		var errs []error
		for err := range errCh {
			errs = append(errs, err)
		}

		return fmt.Errorf("phone record decryption errors: %v", errors.Join(errs...))
	}

	phone.CountryCode = sql.NullString{String: <-countryCodeCh, Valid: true}
	phone.PhoneNumber = sql.NullString{String: <-phNumberCh, Valid: true}
	phone.Extension = sql.NullString{String: <-extCh, Valid: true}
	phone.PhoneType = sql.NullString{String: <-phTypeCh, Valid: true}

	return nil
}
