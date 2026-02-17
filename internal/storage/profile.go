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

// CompleteProfile is a model representing a Profile row with nested Address and Phone slices
// the model includes the database fields for Profile, Address, and Phone
type CompleteProfile struct {
	Profile   *sqlc.Profile
	Addresses []*sqlc.Address
	Phones    []*sqlc.Phone
}

// ProfileStore defines the interface for storing and retrieving user profiles.
type ProfileStore interface {

	// CreateProfile stores a new user profile.
	CreateProfile(ctx context.Context, profile *sqlc.Profile) error

	// GetProfile retrieves a user profile by its username, without including
	// address and phone information.  It does not decrypt sensitive fields.
	GetProfile(ctx context.Context, username string) (*sqlc.Profile, error)

	// GetCompleteProfile retrieves a slice of rows comprised of a join of the profile record and
	// it's related address and phone information.
	GetCompleteProfile(ctx context.Context, username string) (*CompleteProfile, error)

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
		sql:            sqlc.New(db),
		indexer:        i,
		profileCryptor: crypt.NewProfileCryptor(c),
		addressCryptor: crypt.NewAddressCryptor(c),
		phoneCryptor:   crypt.NewPhoneCryptor(c),
	}
}

var _ ProfileStore = (*profileStore)(nil)

// profileStore is the concrete implementation of ProfileStore, using SQL for storage,
// an indexer for searching, and a cryptor for encrypting sensitive profile data.
type profileStore struct {
	sql            *sqlc.Queries
	indexer        data.Indexer
	profileCryptor crypt.ProfileCryptor
	addressCryptor crypt.AddressCryptor
	phoneCryptor   crypt.PhoneCryptor
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
	// encrypt sensitive fields
	if err := ps.profileCryptor.EncryptProfile(profile); err != nil {
		return err
	}

	// store in database
	return ps.sql.SaveProfile(ctx, sqlc.SaveProfileParams{
		Uuid:      profile.Uuid,
		Username:  profile.Username,
		UserIndex: index,
		NickName:  profile.NickName,
		DarkMode:  profile.DarkMode,
		UpdatedAt: profile.UpdatedAt,
		CreatedAt: profile.CreatedAt,
	})
}

// GetProfile retrieves a user profile by its username, without including address and phone information. It does not decrypt sensitive fields.
func (ps *profileStore) GetProfile(ctx context.Context, username string) (*sqlc.Profile, error) {

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

	if err := ps.profileCryptor.DecryptProfile(&profile); err != nil {
		return nil, err
	}

	return &profile, nil
}

// GetCompleteProfile retrieves a user (complete including address and phone) profile by its ID, decrypting sensitive data before returning it.
func (ps *profileStore) GetCompleteProfile(ctx context.Context, username string) (*CompleteProfile, error) {

	// get blind index for username
	index, err := ps.indexer.ObtainBlindIndex(username)
	if err != nil {
		return nil, err
	}

	// retrieve profile from database using blind index
	records, err := ps.sql.FindProfileAddressPhoneRows(ctx, index)
	if err != nil {
		return nil, err
	}

	if len(records) < 1 {
		return nil, fmt.Errorf("no profile-address-phone record rows found for user %s", username)
	}

	// build profile
	profile := sqlc.Profile{
		Uuid:      records[0].ProfileUuid,
		Username:  records[0].Username,
		NickName:  records[0].NickName,
		DarkMode:  records[0].DarkMode,
		UpdatedAt: records[0].ProfileUpdatedAt,
		CreatedAt: records[0].ProfileCreatedAt,
	}

	// build map of unique addressMap and phones -> efficient decryption
	// key is the record uuids
	addressMap := make(map[string]sqlc.Address, len(records))
	phoneMap := make(map[string]sqlc.Phone, len(records))

	// populate the maps
	for _, record := range records {

		// addresses
		if _, ok := addressMap[record.AddressUuid]; !ok {
			addressMap[record.AddressUuid] = sqlc.Address{
				Uuid:         record.AddressUuid,
				Slug:         record.AddressSlug,
				AddressLine1: record.AddressLine1,
				AddressLine2: record.AddressLine2,
				City:         record.City,
				State:        record.State,
				Zip:          record.Zip,
				Country:      record.AddressCountry,
				IsCurrent:    record.AddressIsCurrent,
				UpdatedAt:    record.AddressUpdatedAt,
				CreatedAt:    record.AddressCreatedAt,
			}
		}

		// phones
		if _, ok := phoneMap[record.PhoneUuid]; !ok {
			phoneMap[record.PhoneUuid] = sqlc.Phone{
				Uuid:        record.PhoneUuid,
				Slug:        record.PhoneSlug,
				CountryCode: record.PhoneCountryCode,
				PhoneNumber: record.PhoneNumber,
				Extension:   record.Extension,
				PhoneType:   record.PhoneType,
				IsCurrent:   record.PhoneIsCurrent,
				UpdatedAt:   record.PhoneUpdatedAt,
				CreatedAt:   record.PhoneCreatedAt,
			}
		}
	}

	var (
		wg        sync.WaitGroup
		profileCh = make(chan *sqlc.Profile, 1)
		addressCh = make(chan sqlc.Address, len(addressMap))
		phoneCh   = make(chan sqlc.Phone, len(phoneMap))
		errCh     = make(chan error, 1+len(addressMap)+len(phoneMap))
	)

	// decrypt profile
	wg.Add(1)
	go func(p sqlc.Profile) {
		defer wg.Done()
		if err := ps.profileCryptor.DecryptProfile(&p); err != nil {
			errCh <- err
			return
		}
		profileCh <- &p
	}(profile)

	// decrypt addresses
	for _, address := range addressMap {
		wg.Add(1)
		go func(a sqlc.Address) {
			defer wg.Done()
			if err := ps.addressCryptor.DecryptAddress(&a); err != nil {
				errCh <- err
				return
			}
			addressCh <- a
		}(address)
	}

	// decrypt phones
	for _, phone := range phoneMap {
		wg.Add(1)
		go func(p sqlc.Phone) {
			defer wg.Done()
			if err := ps.phoneCryptor.DecryptPhone(&p); err != nil {
				errCh <- err
				return
			}
			phoneCh <- p
		}(phone)
	}

	// wait for all decryption goroutines to finish
	wg.Wait()
	close(profileCh)
	close(addressCh)
	close(phoneCh)
	close(errCh)

	// check for errs
	if len(errCh) > 0 {
		var errs []error
		for err := range errCh {
			errs = append(errs, err)
		}
		return nil, fmt.Errorf("errors occurred during decryption: %v", errors.Join(errs...))
	}

	// collect the decrypted profile, addresses, and phones
	addresses := make([]*sqlc.Address, 0, len(addressCh))
	for address := range addressCh {
		addresses = append(addresses, &address)
	}

	phones := make([]*sqlc.Phone, 0, len(phoneCh))
	for phone := range phoneCh {
		phones = append(phones, &phone)
	}

	return &CompleteProfile{
		Profile:   <-profileCh,
		Addresses: addresses,
		Phones:    phones,
	}, nil
}

func (ps *profileStore) UpdateProfile(ctx context.Context, profile *sqlc.Profile) error {

	// encrypt sensitive fields
	if err := ps.profileCryptor.EncryptProfile(profile); err != nil {
		return err
	}

	// update in database
	return ps.sql.UpdateProfile(ctx, sqlc.UpdateProfileParams{
		NickName:  profile.NickName,
		DarkMode:  profile.DarkMode,
		UpdatedAt: profile.UpdatedAt,
		Uuid:      profile.Uuid,
	})
}

func (ps *profileStore) DeleteProfile(ctx context.Context, userIndex string) error {
	return ps.sql.DeleteProfile(ctx, userIndex)
}
