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
	DecryptProfile(profile *sqlc.Profile) error
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
	}

	if profile.NickName.Valid && len(profile.NickName.String) > 0 {
		wg.Add(1)
		go pc.cryptor.EncryptField(
			"nickname",
			profile.NickName.String,
			nicknameCh,
			errCh,
			&wg,
		)
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

	// username is required, so we can assume it will be present in the channel
	// but good practice to check anyway
	username, ok := <-usernameCh
	if !ok {
		return errors.New("username field encryption failed and did not return a value")
	} else {
		profile.Username = username
	}

	// nickname is optional
	nickname, ok := <-nicknameCh
	if ok {
		profile.NickName = sql.NullString{String: nickname, Valid: true}
	} else {
		profile.NickName = sql.NullString{String: "", Valid: false}
	}

	return nil
}

// DecryptProfile decrypts the fields of a user profile after retrieval.
func (pc *profileCryptor) DecryptProfile(profile *sqlc.Profile) error {

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

	if profile.NickName.Valid && len(profile.NickName.String) > 0 {
		wg.Add(1)
		go pc.cryptor.DecryptField(
			"nickname",
			profile.NickName.String,
			nicknameCh,
			errCh,
			&wg,
		)
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

	// get username from channel
	username, ok := <-usernameCh
	if !ok {
		return errors.New("username field decryption failed and did not return a value")
	} else {
		profile.Username = username
	}

	// nickname is optional, get from channel if exists
	nickname, ok := <-nicknameCh
	if ok {
		profile.NickName = sql.NullString{String: nickname, Valid: true}
	} else {
		profile.NickName = sql.NullString{String: "", Valid: false}
	}

	return nil
}
