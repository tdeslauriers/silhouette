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

// PhoneStore provides persistance operations for phone numbers
type PhoneStore interface {

	// GetPhone retrieves a user's phone number from the database and decrypts the record.
	GetPhone(ctx context.Context, slug, username string) (*sqlc.Phone, error)

	// CountPhones retrieves a count of how many phone records exist for a given user.
	CountPhones(ctx context.Context, username string) (int64, error)

	// CountPrimaryPhones retrieves a count of how many primary phone records exist for a given user.
	CountPrimaryPhones(ctx context.Context, username string) (int64, error)

	// GetPhonesByUser retrieves all phone records for a given user, and decrypts the records.
	GetPhonesByUser(ctx context.Context, username string) ([]*sqlc.Phone, error)

	// CreatePhone creates a new phone record in the database, encrypting the fields before storage.
	CreatePhone(ctx context.Context, phone *sqlc.Phone) error

	// UpdatePhone updates an existing phone record in the database, encrypting the fields before storage.
	UpdatePhone(ctx context.Context, phone *sqlc.Phone) error

	// DeletePhone deletes a phone record from the database.
	DeletePhone(ctx context.Context, uuid string) error
}

// NewPhoneStore creates a new instance of PhoneStore and
// returns a pointer to an underlying implementation
func NewPhoneStore(db *sql.DB, i data.Indexer, c data.Cryptor) PhoneStore {

	return &phoneStore{
		sql:     sqlc.New(db),
		indexer: i,
		cryptor: crypt.NewPhoneCryptor(c),
	}
}

var _ PhoneStore = (*phoneStore)(nil)

// phoneStore is the concrete implementation of the PhoneStore interface, providing
// persistence operations for phone numbers
type phoneStore struct {
	sql     *sqlc.Queries
	indexer data.Indexer
	cryptor crypt.PhoneCryptor
}

// GetPhone retrieves a user's phone number from the database and decrypts the record.
func (ps *phoneStore) GetPhone(ctx context.Context, slug, username string) (*sqlc.Phone, error) {

	// get the blind slugIndex for the phone slug
	slugIndex, err := ps.indexer.ObtainBlindIndex(slug)
	if err != nil {
		return nil, err
	}

	// get the blind index for the username
	userIndex, err := ps.indexer.ObtainBlindIndex(username)
	if err != nil {
		return nil, err
	}

	// fetch the phone record for the given user and slug
	phone, err := ps.sql.FindPhoneByUser(ctx, sqlc.FindPhoneByUserParams{
		SlugIndex: slugIndex,
		UserIndex: userIndex,
	})
	if err != nil {
		return nil, err
	}

	// decrypt the phone record
	if err := ps.cryptor.DecryptPhone(&phone); err != nil {
		return nil, err
	}

	return &phone, nil
}

// CountPhones retrieves a count of how many phone records exist for a given user.
func (ps *phoneStore) CountPhones(ctx context.Context, username string) (int64, error) {

	// get the blind index for the username
	userIndex, err := ps.indexer.ObtainBlindIndex(username)
	if err != nil {
		return 0, err
	}

	// fetch count from the db
	return ps.sql.CountPhonesForUser(ctx, userIndex)
}

// CountPrimaryPhones retrieves a count of how many primary phone records exist for a given user.
func (ps *phoneStore) CountPrimaryPhones(ctx context.Context, username string) (int64, error) {

	// get the blind index for the username
	userIndex, err := ps.indexer.ObtainBlindIndex(username)
	if err != nil {
		return 0, err
	}

	// fetch count from the db
	return ps.sql.CountPrimaryPhonesForUser(ctx, userIndex)
}

// GetPhonesByUser retrieves all phone records for a given user, and decrypts the records.
func (ps *phoneStore) GetPhonesByUser(ctx context.Context, username string) ([]*sqlc.Phone, error) {

	// get the blind index for the username
	userIndex, err := ps.indexer.ObtainBlindIndex(username)
	if err != nil {
		return nil, err
	}

	// fetch the phone records for the given user
	records, err := ps.sql.FindPhonesByUser(ctx, userIndex)
	if err != nil {
		return nil, err
	}

	var phones []*sqlc.Phone

	// return empty if empty result set
	if len(records) < 1 {
		return phones, nil
	}

	// if one, omit concurrency loop and just decrypt and return
	if len(records) == 1 {

		phone := records[0]

		if err := ps.cryptor.DecryptPhone(&phone); err != nil {
			return nil, err
		}

		return []*sqlc.Phone{&phone}, nil
	}

	// setup concurrency loop to decrypt phone records in parallel if more than one record
	var (
		wg      sync.WaitGroup
		phoneCh = make(chan *sqlc.Phone, len(records))
		errCh   = make(chan error, len(records))
	)

	for _, r := range records {
		wg.Add(1)

		go func(phone sqlc.Phone) {
			defer wg.Done()

			if err := ps.cryptor.DecryptPhone(&phone); err != nil {
				errCh <- err
				return
			}

			phoneCh <- &phone
		}(r)
	}

	wg.Wait()
	close(phoneCh)
	close(errCh)

	// check if any errors were returned during decryption
	if len(errCh) > 0 {
		var errs []error
		for err := range errCh {
			errs = append(errs, err)
		}
		return nil, fmt.Errorf("encountered errors during decryption: %v", errors.Join(errs...))
	}

	// compile decrypted records into slice
	for p := range phoneCh {
		phones = append(phones, p)
	}

	return phones, nil
}

// CreatePhone creates a new phone record in the database, encrypting the fields before storage.
func (ps *phoneStore) CreatePhone(ctx context.Context, phone *sqlc.Phone) error {

	// if no uuid, create one
	// this should never happen since the service layer should create prior to calling
	if phone.Uuid == "" {
		id, err := uuid.NewRandom()
		if err != nil {
			return err
		}
		phone.Uuid = id.String()
	}

	// if no slug, create one
	// this should never happen since the service layer should create prior to calling
	if phone.Slug == "" {
		slug, err := uuid.NewRandom()
		if err != nil {
			return err
		}
		phone.Slug = slug.String()
	}

	// generate slug index
	slugIndex, err := ps.indexer.ObtainBlindIndex(phone.Slug)
	if err != nil {
		return err
	}

	if err := ps.cryptor.EncryptPhone(phone); err != nil {
		return err
	}

	return ps.sql.SavePhone(ctx, sqlc.SavePhoneParams{
		Uuid:        phone.Uuid,
		Slug:        phone.Slug,
		SlugIndex:   slugIndex,
		CountryCode: phone.CountryCode,
		PhoneNumber: phone.PhoneNumber,
		Extension:   phone.Extension,
		PhoneType:   phone.PhoneType,
		IsCurrent:   phone.IsCurrent,
		IsPrimary:   phone.IsPrimary,
		UpdatedAt:   phone.UpdatedAt,
		CreatedAt:   phone.CreatedAt,
	})
}

// UpdatePhone updates an existing phone record in the database, encrypting the fields before storage.
func (ps *phoneStore) UpdatePhone(ctx context.Context, phone *sqlc.Phone) error {

	if err := ps.cryptor.EncryptPhone(phone); err != nil {
		return err
	}

	return ps.sql.UpdatePhone(ctx, sqlc.UpdatePhoneParams{
		CountryCode: phone.CountryCode,
		PhoneNumber: phone.PhoneNumber,
		Extension:   phone.Extension,
		PhoneType:   phone.PhoneType,
		IsCurrent:   phone.IsCurrent,
		IsPrimary:   phone.IsPrimary,
		UpdatedAt:   phone.UpdatedAt,
		Uuid:        phone.Uuid,
	})
}

// DeletePhone deletes a phone record from the database.
func (ps *phoneStore) DeletePhone(ctx context.Context, uuid string) error {
	return ps.sql.DeletePhone(ctx, uuid)
}
