package crypt

import (
	"database/sql"
	"errors"
	"fmt"
	"sync"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/silhouette/internal/storage/sql/sqlc"
)

// ProfileCryptor provides encryption and decryption operations for user profiles
type ProfileCryptor interface {

	// EncryptProfile encrypts the fields of a user profile before storage.
	EncryptProfile(profile *sqlc.Profile) error

	// DecryptSimpleProfile decrypts the fields of a user profile after retrieval.
	DecryptProfile(profile *sqlc.FindProfileRow) error

	// DecryptCompleteProfile decrypts the fields of a complete user profile after retrieval, which
	// includes address and phone information.
	DecryptCompleteProfile(profile *sqlc.FindCompleteProfileRow) error
}

// NewProfileCryptor creates a new instance of ProfileCryptor
func NewProfileCryptor(c data.Cryptor) ProfileCryptor {
	return &profileCryptor{
		cryptor: c,
	}
}

var _ ProfileCryptor = (*profileCryptor)(nil)

// profileCryptor is the concrete implementation of the ProfileCryptor interface,
// providing encryption and decryption operations for user profiles
type profileCryptor struct {
	cryptor data.Cryptor
}

// EncryptProfile encrypts the fields of a user profile before storage.
func (pc *profileCryptor) EncryptProfile(profile *sqlc.Profile) error {

	var (
		wg sync.WaitGroup

		usernameCh = make(chan string, 1)
		nicknameCh = make(chan string, 1)

		errCh = make(chan error, 2)
	)

	if len(profile.Username) > 0 {
		wg.Add(1)
		go pc.cryptor.EncryptField(
			"username",
			profile.Username,
			usernameCh,
			errCh,
			&wg,
		)
	} else {
		errCh <- errors.New("username field is empty so it cannot be encrypted")
	}

	if profile.NickName.Valid {
		wg.Add(1)
		go pc.cryptor.EncryptField(
			"nickname",
			profile.NickName.String,
			nicknameCh,
			errCh,
			&wg,
		)
	} else {
		nicknameCh <- ""
	}

	wg.Wait()
	close(usernameCh)
	close(nicknameCh)
	close(errCh)

	if len(errCh) > 0 {
		var errs []error
		for err := range errCh {
			errs = append(errs, err)
		}

		return fmt.Errorf("profile record encryption errors: %v", errors.Join(errs...))
	}

	profile.Username = <-usernameCh
	profile.NickName = sql.NullString{String: <-nicknameCh, Valid: true}

	return nil
}

// DecryptProfile decrypts the fields of a user profile after retrieval.
func (pc *profileCryptor) DecryptProfile(profile *sqlc.FindProfileRow) error {

	var (
		wg sync.WaitGroup

		usernameCh = make(chan string, 1)
		nicknameCh = make(chan string, 1)

		errCh = make(chan error, 2)
	)

	if len(profile.Username) > 0 {
		wg.Add(1)
		go pc.cryptor.DecryptField(
			"username",
			profile.Username,
			usernameCh,
			errCh,
			&wg,
		)
	} else {
		errCh <- errors.New("username field is empty so it cannot be decrypted")
	}

	if profile.NickName.Valid {
		wg.Add(1)
		go pc.cryptor.DecryptField(
			"nickname",
			profile.NickName.String,
			nicknameCh,
			errCh,
			&wg,
		)
	} else {
		nicknameCh <- ""
	}

	wg.Wait()
	close(usernameCh)
	close(nicknameCh)
	close(errCh)

	if len(errCh) > 0 {
		var errs []error
		for err := range errCh {
			errs = append(errs, err)
		}

		return fmt.Errorf("profile record decryption errors: %v", errors.Join(errs...))
	}

	profile.Username = <-usernameCh
	profile.NickName = sql.NullString{String: <-nicknameCh, Valid: true}

	return nil
}

// DecryptCompleteProfile decrypts the fields of a complete user profile after retrieval, which
// includes address and phone information.
func (pc *profileCryptor) DecryptCompleteProfile(profile *sqlc.FindCompleteProfileRow) error {

	var (
		wg sync.WaitGroup

		// profile fields channels
		usernameCh = make(chan string, 1)
		nicknameCh = make(chan string, 1)

		// address fields channels
		addressLine1Ch = make(chan string, 1)
		addressLine2Ch = make(chan string, 1)
		cityCh         = make(chan string, 1)
		stateCh        = make(chan string, 1)
		zipCh          = make(chan string, 1)
		countryCh      = make(chan string, 1)

		// phone fields channels
		countryCodeCh = make(chan string, 1)
		phoneNumberCh = make(chan string, 1)
		extensionCh   = make(chan string, 1)
		phoneTypeCh   = make(chan string, 1)

		errCh = make(chan error, 12)
	)

	// decrypt profile fields
	if len(profile.Username) > 0 {
		wg.Add(1)
		go pc.cryptor.DecryptField(
			"username",
			profile.Username,
			usernameCh,
			errCh,
			&wg,
		)
	} else {
		errCh <- errors.New("username field is empty so it cannot be decrypted")
	}

	if profile.NickName.Valid {
		wg.Add(1)
		go pc.cryptor.DecryptField(
			"nickname",
			profile.NickName.String,
			nicknameCh,
			errCh,
			&wg,
		)
	} else {
		nicknameCh <- ""
	}

	// decrypt address fields: if they exist
	if profile.AddressLine1.Valid {
		wg.Add(1)
		go pc.cryptor.DecryptField(
			"address_line_1",
			profile.AddressLine1.String,
			addressLine1Ch,
			errCh,
			&wg,
		)
	} else {
		addressLine1Ch <- ""
	}

	if profile.AddressLine2.Valid {
		wg.Add(1)
		go pc.cryptor.DecryptField(
			"address_line_2",
			profile.AddressLine2.String,
			addressLine2Ch,
			errCh,
			&wg,
		)
	} else {
		addressLine2Ch <- ""
	}

	if profile.City.Valid {
		wg.Add(1)
		go pc.cryptor.DecryptField(
			"city",
			profile.City.String,
			cityCh,
			errCh,
			&wg,
		)
	} else {
		cityCh <- ""
	}

	if profile.State.Valid {
		wg.Add(1)
		go pc.cryptor.DecryptField(
			"state",
			profile.State.String,
			stateCh,
			errCh,
			&wg,
		)
	} else {
		stateCh <- ""
	}

	if profile.Zip.Valid {
		wg.Add(1)
		go pc.cryptor.DecryptField(
			"zip",
			profile.Zip.String,
			zipCh,
			errCh,
			&wg,
		)
	} else {
		zipCh <- ""
	}

	if profile.AddressCountry.Valid {
		wg.Add(1)
		go pc.cryptor.DecryptField(
			"country",
			profile.AddressCountry.String,
			countryCh,
			errCh,
			&wg,
		)
	} else {
		countryCh <- ""
	}

	if profile.PhoneCountryCode.Valid {
		wg.Add(1)
		go pc.cryptor.DecryptField(
			"phone_country_code",
			profile.PhoneCountryCode.String,
			countryCodeCh,
			errCh,
			&wg,
		)
	} else {
		countryCodeCh <- ""
	}

	if profile.PhoneNumber.Valid {
		wg.Add(1)
		go pc.cryptor.DecryptField(
			"phone_number",
			profile.PhoneNumber.String,
			phoneNumberCh,
			errCh,
			&wg,
		)
	} else {
		phoneNumberCh <- ""
	}

	if profile.Extension.Valid {
		wg.Add(1)
		go pc.cryptor.DecryptField(
			"phone_extension",
			profile.Extension.String,
			extensionCh,
			errCh,
			&wg,
		)
	} else {
		extensionCh <- ""
	}

	if profile.PhoneType.Valid {
		wg.Add(1)
		go pc.cryptor.DecryptField(
			"phone_type",
			profile.PhoneType.String,
			phoneTypeCh,
			errCh,
			&wg,
		)
	} else {
		phoneTypeCh <- ""
	}

	wg.Wait()
	close(usernameCh)
	close(nicknameCh)
	close(addressLine1Ch)
	close(addressLine2Ch)
	close(cityCh)
	close(stateCh)
	close(zipCh)
	close(countryCh)
	close(countryCodeCh)
	close(phoneNumberCh)
	close(extensionCh)
	close(phoneTypeCh)
	close(errCh)

	if len(errCh) > 0 {
		var errs []error
		for err := range errCh {
			errs = append(errs, err)
		}

		return fmt.Errorf("profile record decryption errors: %v", errors.Join(errs...))
	}

	profile.Username = <-usernameCh
	profile.NickName = sql.NullString{String: <-nicknameCh, Valid: true}
	profile.AddressLine1 = sql.NullString{String: <-addressLine1Ch, Valid: true}
	profile.AddressLine2 = sql.NullString{String: <-addressLine2Ch, Valid: true}
	profile.City = sql.NullString{String: <-cityCh, Valid: true}
	profile.State = sql.NullString{String: <-stateCh, Valid: true}
	profile.Zip = sql.NullString{String: <-zipCh, Valid: true}
	profile.AddressCountry = sql.NullString{String: <-countryCh, Valid: true}
	profile.PhoneCountryCode = sql.NullString{String: <-countryCodeCh, Valid: true}
	profile.PhoneNumber = sql.NullString{String: <-phoneNumberCh, Valid: true}
	profile.Extension = sql.NullString{String: <-extensionCh, Valid: true}
	profile.PhoneType = sql.NullString{String: <-phoneTypeCh, Valid: true}

	return nil
}
