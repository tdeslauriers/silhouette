package storage

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/silhouette/internal/storage/crypt"
	"github.com/tdeslauriers/silhouette/internal/storage/sql/sqlc"
)

// ProfileStore defines the interface for storing and retrieving user profiles.
type ProfileStore interface {

	// CreateProfile stores a new user profile.
	CreateProfile(ctx context.Context, profile *sqlc.Profile) error

	// GetProfile retrieves a user profile by its username, without including
	// address and phone information.  It does not decrypt sensitive fields.
	GetProfile(ctx context.Context, username string) (*sqlc.FindProfileRow, error)

	// GetCompleteProfile retrieves a (complete including address and phone) user profile by its ID.
	// It decrypts sensitive fields before returning the profile.
	GetCompleteProfile(ctx context.Context, username string) (*sqlc.FindCompleteProfileRow, error)

	// UpdateProfile updates an existing user profile.
	UpdateProfile(ctx context.Context, profile *sqlc.Profile) error

	// DeleteProfile deletes a user profile by its userIndex.
	DeleteProfile(ctx context.Context, userIndex string) error
}

// NewProfileStore creates a new instance of ProfileStore, returning
// a concrete implementation that uses SQL for storage, an indexer for searching,
// and a cryptor for encrypting sensitive profile data.
func NewProfileStore(db *sql.DB, i data.Indexer, c data.Cryptor) ProfileStore {
	return &profileStore{
		sql:     sqlc.New(db),
		indexer: i,
		cryptor: crypt.NewProfileCryptor(c),
	}
}

var _ ProfileStore = (*profileStore)(nil)

// profileStore is the concrete implementation of ProfileStore, using SQL for storage,
// an indexer for searching, and a cryptor for encrypting sensitive profile data.
type profileStore struct {
	sql     *sqlc.Queries
	indexer data.Indexer
	cryptor crypt.ProfileCryptor
}

// CreateProfile stores a new user profile, encrypting sensitive data before saving it to the database.
func (ps *profileStore) CreateProfile(ctx context.Context, profile *sqlc.Profile) error {

	// would expect uuid to already exist, but check and create if necessary
	if profile.Uuid == "" {
		id, err := uuid.NewRandom()
		if err != nil {
			return fmt.Errorf("failed to create uuid for new profile: %s, %v", profile.Username, err)
		}
		profile.Uuid = id.String()
	}

	// build blind index for username
	index, err := ps.indexer.ObtainBlindIndex(profile.Username)
	if err != nil {
		return err
	}
	profile.UserIndex = index

	// encrypt sensitive fields
	if err := ps.cryptor.EncryptProfile(profile); err != nil {
		return err
	}

	// store in database
	return ps.sql.SaveProfile(ctx, sqlc.SaveProfileParams{
		Uuid:      profile.Uuid,
		Username:  profile.Username,
		UserIndex: profile.UserIndex,
		NickName:  profile.NickName,
		DarkMode:  profile.DarkMode,
		UpdatedAt: profile.UpdatedAt,
		CreatedAt: profile.CreatedAt,
	})
}

// GetSimpleProfile retrieves a user profile by its username, without including address and phone information. It does not decrypt sensitive fields.
func (ps *profileStore) GetProfile(ctx context.Context, username string) (*sqlc.FindProfileRow, error) {

	// get blind index for username
	index, err := ps.indexer.ObtainBlindIndex(username)
	if err != nil {
		return nil, err
	}

	// retrieve profile from database using blind index
	profile, err := ps.sql.FindProfile(ctx, index)
	if err != nil {
		return nil, err
	}

	if err := ps.cryptor.DecryptProfile(&profile); err != nil {
		return nil, err
	}

	return &profile, nil
}

// GetCompleteProfile retrieves a user (complete including address and phone) profile by its ID, decrypting sensitive data before returning it.
func (ps *profileStore) GetCompleteProfile(ctx context.Context, username string) (*sqlc.FindCompleteProfileRow, error) {

	// get blind index for username
	index, err := ps.indexer.ObtainBlindIndex(username)
	if err != nil {
		return nil, err
	}

	// retrieve profile from database using blind index
	profile, err := ps.sql.FindCompleteProfile(ctx, index)
	if err != nil {
		return nil, err
	}

	// decrypt sensitive fields
	if err := ps.cryptor.DecryptCompleteProfile(&profile); err != nil {
		return nil, err
	}

	return &profile, nil
}

func (ps *profileStore) UpdateProfile(ctx context.Context, profile *sqlc.Profile) error {

	// encrypt sensitive fields
	if err := ps.cryptor.EncryptProfile(profile); err != nil {
		return err
	}

	// update in database
	return ps.sql.UpdateProfile(ctx, sqlc.UpdateProfileParams{
		NickName:  profile.NickName,
		DarkMode:  profile.DarkMode,
		UpdatedAt: profile.UpdatedAt,
		UserIndex: profile.UserIndex,
	})
}

func (ps *profileStore) DeleteProfile(ctx context.Context, userIndex string) error {
	return ps.sql.DeleteProfile(ctx, userIndex)
}
