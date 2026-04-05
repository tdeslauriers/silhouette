package address

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	exo "github.com/tdeslauriers/carapace/pkg/connect/grpc"
	api "github.com/tdeslauriers/silhouette/api/v1"
	"github.com/tdeslauriers/silhouette/internal/auth"
	"github.com/tdeslauriers/silhouette/internal/storage/sql/sqlc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// CreateAddress creates a new address and xref record for a user in the database.
func (as *addressServer) CreateAddress(ctx context.Context, req *api.CreateAddressRequest) (*api.Address, error) {

	telemetry, ok := exo.GetTelemetryFromContext(ctx)
	if !ok {
		// this should not be possible since the interceptor will have generated new if missing
		as.logger.Warn("failed to get telmetry from incoming context")
	}

	// append telemetry fields
	log := as.logger.With(telemetry.TelemetryFields()...)

	// get authz context
	authCtx, err := auth.GetAuthContext(ctx)
	if err != nil {
		log.Error("failed to get auth context", "err", err.Error())
		return nil, status.Error(codes.Unauthenticated, "failed to get auth context")
	}

	// validate user claims exist in the auth context
	if authCtx.UserClaims == nil {
		log.Error("auth context missing user claims")
		return nil, status.Error(codes.Unauthenticated, "auth context missing user claims")
	}

	// validate service claims exist in the auth context
	if authCtx.SvcClaims == nil {
		log.Error("auth context missing service claims")
		return nil, status.Error(codes.Unauthenticated, "auth context missing service claims")
	}

	// add actors to audit log
	log = log.
		With("actor", authCtx.UserClaims.Subject).
		With("requesting_service", authCtx.SvcClaims.Subject)

	// prepare req fields for use
	username := strings.TrimSpace(req.GetUsername())

	// authorize the request
	if err := auth.AuthorizeRequest(authCtx, username); err != nil {
		log.Error("failed to authorize request", "err", err.Error())
		return nil, status.Error(codes.PermissionDenied, "access denied")
	}

	// validate fields
	if err := ValidateCmd(req); err != nil {
		log.Error("invalid create-address request", "err", err.Error())
		return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("invalid create-address request: %s", err.Error()))
	}

	// get the porfile record to validate user exists in the service
	// it should never happen that a valid user would not have a profile record
	// need the profile uuid for the xref record
	profile, err := as.profileStore.GetProfile(ctx, username)
	if err != nil {
		log.Error(fmt.Sprintf("failed to lookup profile for %s", username), "err", err.Error())
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to look up profile for %s", username))
	}

	// check how many address records currently exist for the user
	// only allowed to have 3 address records, including non-current records
	addressCount, err := as.addressStore.CountAddresses(ctx, username)
	if err != nil {
		log.Error(fmt.Sprintf("failed to get address count for %s", username), "err", err.Error())
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to get address count for %s", username))
	}

	if addressCount >= 3 {
		log.Error(fmt.Sprintf("address record limit reached for %s - count %d", username, addressCount))
		return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("address record limit reached for %s", username))
	}

	// create address record
	id, err := uuid.NewRandom()
	if err != nil {
		log.Error(fmt.Sprintf("failed to generate uuid for %s's new address record", username), "err", err.Error())
		return nil, status.Error(codes.Internal, "failed to generate uuid for new address record")
	}

	// create slug
	slug, err := uuid.NewRandom()
	if err != nil {
		log.Error(fmt.Sprintf("failed to generate slug for %s's new address record", username), "err", err.Error())
		return nil, status.Error(codes.Internal, "failed to generate slug for new address record")
	}

	// prepare fields
	streetAddress := strings.TrimSpace(req.GetStreetAddress())
	city := strings.TrimSpace(req.GetCity())
	stateProvince := strings.TrimSpace(req.GetStateProvince())
	postalCode := strings.TrimSpace(req.GetPostalCode())
	country := strings.TrimSpace(req.GetCountry())

	var streetAddress_2 string
	if len(req.GetStreetAddress_2()) > 0 {
		streetAddress_2 = strings.TrimSpace(req.GetStreetAddress_2())
	}

	now := time.Now().UTC()

	toAdd := &sqlc.Address{
		Uuid: id.String(),
		Slug: slug.String(),
		// SlugIndex not needed for update
		AddressLine1: sql.NullString{String: streetAddress, Valid: streetAddress != ""},
		AddressLine2: sql.NullString{String: streetAddress_2, Valid: streetAddress_2 != ""},
		City:         sql.NullString{String: city, Valid: city != ""},
		State:        sql.NullString{String: stateProvince, Valid: stateProvince != ""},
		Zip:          sql.NullString{String: postalCode, Valid: postalCode != ""},
		Country:      sql.NullString{String: country, Valid: country != ""},
		IsCurrent:    req.GetIsCurrent(),
		UpdatedAt:    now,
		CreatedAt:    now,
	}

	// need to check if the new record is set to primary and
	// if so, make sure there are no other primary records
	switch {
	case !toAdd.IsCurrent && !req.GetIsPrimary():
		// if the new record is non-current and non-primary, do nothing - this is valid
		toAdd.IsPrimary = false
	case toAdd.IsCurrent && !req.GetIsPrimary():
		// if the new record is current and non-primary, do nothing - this is valid
		toAdd.IsPrimary = false
	case !toAdd.IsCurrent && req.GetIsPrimary():
		// cannot create a non current record as primary - this is invalid
		log.Error(fmt.Sprintf("invalid address record for %s - non-current record cannot be primary", username))
		return nil, status.Error(codes.InvalidArgument, "invalid address record - non-current record cannot be primary")
	case toAdd.IsCurrent && req.GetIsPrimary():
		// user should not have current primary address records

		// get count of how many primary address records exist for the user
		count, err := as.addressStore.CountPrimaryAddresses(ctx, username)
		if err != nil {
			log.Error(fmt.Sprintf("failed to get primary address count for %s", username), "err", err.Error())
			return nil, status.Error(codes.Internal, fmt.Sprintf("failed to get primary address count for %s", username))
		}

		if count > 0 {
			log.Error(fmt.Sprintf("primary address record already exists for %s - cannot create another primary record", username))
			return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("primary address record already exists for %s - cannot create another primary record", username))
		}

		toAdd.IsPrimary = true
	}

	// sanity check: ensure final state does not include primary == true and is_current == false - this is invalid
	if toAdd.IsPrimary && !toAdd.IsCurrent {
		log.Error(fmt.Sprintf("invalid address record for %s - non-current record cannot be primary", username))
		return nil, status.Error(codes.InvalidArgument, "invalid address record - non-current record cannot be primary")
	}

	// persist address record
	if err := as.addressStore.CreateAddress(ctx, toAdd); err != nil {
		log.Error(fmt.Sprintf("failed to create address record for %s", username), "err", err.Error())
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to create address record for %s", username))
	}

	log.Info(fmt.Sprintf("successfuly persisted address record - slug %s for %s", slug, username))

	// persist xref record
	if err := as.xrefStore.CreateProfileAddressXref(ctx, profile.Uuid, toAdd.Uuid); err != nil {
		log.Error(fmt.Sprintf("failed to create address xref record for %s", username), "err", err.Error())
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to create address xref record for %s", username))
	}

	log.Info(fmt.Sprintf("succcessfully persisted profile-address record for %s and address - slug %s", username, slug))

	// return the created address record
	// note: cant user record cuz model is encrypted when it is saved.
	return &api.Address{
		Uuid:            id.String(),
		Slug:            slug.String(),
		StreetAddress:   streetAddress,
		StreetAddress_2: proto.String(streetAddress_2),
		City:            city,
		StateProvince:   stateProvince,
		PostalCode:      postalCode,
		Country:         country,
		IsCurrent:       toAdd.IsCurrent,
		IsPrimary:       toAdd.IsPrimary,
		UpdatedAt:       timestamppb.New(toAdd.UpdatedAt),
		CreatedAt:       timestamppb.New(toAdd.CreatedAt),
	}, nil
}
