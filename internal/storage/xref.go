package storage

import (
	"context"
	"database/sql"
	"time"

	"github.com/tdeslauriers/silhouette/internal/storage/sql/sqlc"
)

// XrefStore defines the interface for managing cross-references between profiles and other entities like phones and addresses.
type XrefStore interface {

	// CreateProfilePhoneXref creates a new cross-reference between a profile and a phone record.
	CreateProfilePhoneXref(ctx context.Context, profileId, phoneId string) error

	// RemovePhoneXrefByPhone removes the cross-reference between a profile and a phone record by phone ID.
	RemovePhoneXrefByPhone(ctx context.Context, phoneId string) error

	// RemovePhoneXrefByProfile removes the cross-reference between a profile and a phone record by profile ID.
	RemovePhoneXrefByProfile(ctx context.Context, profileId string) error

	// CreateProfileAddressXref creates a new cross-reference between a profile and an address record.
	CreateProfileAddressXref(ctx context.Context, profileId, addressId string) error

	// RemoveAddressXrefByAddress removes the cross-reference between a profile and an address record by address ID.
	RemoveAddressXrefByAddress(ctx context.Context, addressId string) error

	// RemoveAddressXrefByProfile removes the cross-reference between a profile and an address record by profile ID.
	RemoveAddressXrefByProfile(ctx context.Context, profileId string) error
}

// NewXrefStore creates a new instance of XrefStore interface, returning
// a pointer to a concrete implementation of the XrefStore.
func NewXrefStore(db *sql.DB) XrefStore {
	return &xrefStore{
		sql: sqlc.New(db),
	}
}

var _ XrefStore = (*xrefStore)(nil)

// xrefStore is a concrete implementation of the XrefStore interface.
type xrefStore struct {
	sql *sqlc.Queries
}

// CreateProfilePhoneXref creates a new cross-reference between a profile and a phone record.
func (x *xrefStore) CreateProfilePhoneXref(ctx context.Context, profileId, phoneId string) error {

	return x.sql.InsertProfilePhone(ctx, sqlc.InsertProfilePhoneParams{
		ID:          0, // Auto-increment ID
		ProfileUuid: profileId,
		PhoneUuid:   phoneId,
		CreatedAt:   time.Now().UTC(),
	})
}

// RemovePhoneXrefByPhone removes the cross-reference between a profile and a phone record by phone ID.
func (x *xrefStore) RemovePhoneXrefByPhone(ctx context.Context, phoneId string) error {

	return x.sql.DeleteProfilePhoneByPhoneUuid(ctx, phoneId)
}

// RemovePhoneXrefByProfile removes the cross-reference between a profile and a phone record by profile ID.
func (x *xrefStore) RemovePhoneXrefByProfile(ctx context.Context, profileId string) error {

	return x.sql.DeleteProfilePhoneByProfileUuid(ctx, profileId)
}

// CreateProfileAddressXref creates a new cross-reference between a profile and an address record.
func (x *xrefStore) CreateProfileAddressXref(ctx context.Context, profileId, addressId string) error {

	return x.sql.InsertProfileAddress(ctx, sqlc.InsertProfileAddressParams{
		ID:          0, // Auto-increment ID
		ProfileUuid: profileId,
		AddressUuid: addressId,
		CreatedAt:   time.Now().UTC(),
	})
}

// RemoveAddressXrefByAddress removes the cross-reference between a profile and an address record by address ID.
func (x *xrefStore) RemoveAddressXrefByAddress(ctx context.Context, addressId string) error {

	return x.sql.DeleteProfileAddressByAddressUuid(ctx, addressId)
}

// RemoveAddressXrefByProfile removes the cross-reference between a profile and an address record by profile ID.
func (x *xrefStore) RemoveAddressXrefByProfile(ctx context.Context, profileId string) error {

	return x.sql.DeleteProfileAddressByProfileUuid(ctx, profileId)
}
