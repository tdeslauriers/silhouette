package storage

import (
	"context"
	"database/sql"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/silhouette/internal/storage/crypt"
	"github.com/tdeslauriers/silhouette/internal/storage/sql/sqlc"
)

// PhoneStore provides persistance operations for phone numbers
type PhoneStore interface {

	// GetPhone retrieves a user's phone number from the database and decrypts the record.
	GetUsersPhone(ctx context.Context, slug, username string) (*sqlc.Phone, error)

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
func (ps *phoneStore) GetUsersPhone(ctx context.Context, slug, username string) (*sqlc.Phone, error) {

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

// CreatePhone creates a new phone record in the database, encrypting the fields before storage.
func (ps *phoneStore) CreatePhone(ctx context.Context, phone *sqlc.Phone) error {

	if err := ps.cryptor.EncryptPhone(phone); err != nil {
		return err
	}

	return ps.sql.SavePhone(ctx, sqlc.SavePhoneParams{
		Uuid:        phone.Uuid,
		CountryCode: phone.CountryCode,
		PhoneNumber: phone.PhoneNumber,
		Extension:   phone.Extension,
		PhoneType:   phone.PhoneType,
		IsCurrent:   phone.IsCurrent,
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
		UpdatedAt:   phone.UpdatedAt,
		Uuid:        phone.Uuid,
	})
}

// DeletePhone deletes a phone record from the database.
func (ps *phoneStore) DeletePhone(ctx context.Context, uuid string) error {
	return ps.sql.DeletePhone(ctx, uuid)
}
