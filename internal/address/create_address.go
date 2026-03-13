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

	// add actors to audit log
	log = log.
		With("actor", authCtx.UserClaims.Subject).
		With("requesting_service", authCtx.SvcClaims.Subject)

	// authorize the request
	if err := auth.AuthorizeRequest(authCtx, req.GetUsername()); err != nil {
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
	profile, err := as.profileStore.GetProfile(ctx, req.GetUsername())
	if err != nil {
		log.Error(fmt.Sprintf("failed to lookup profile for %s", req.GetUsername()), "err", err.Error())
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to look up profile for %s", req.GetUsername()))
	}

	// check how many address records currently exist for the user
	// only allowed to have 3 address records, including non-current records
	addressCount, err := as.addressStore.CountAddresses(ctx, req.GetUsername())
	if err != nil {
		log.Error(fmt.Sprintf("failed to get address count for %s", req.GetUsername()), "err", err.Error())
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to get address count for %s", req.GetUsername()))
	}

	if addressCount >= 3 {
		log.Error(fmt.Sprintf("address record limit reached for %s - count %d", req.GetUsername(), addressCount))
		return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("address record limit reached for %s", req.GetUsername()))
	}

	// create address record
	id, err := uuid.NewRandom()
	if err != nil {
		log.Error(fmt.Sprintf("failed to generate uuid for %s's new address record", req.GetUsername()), "err", err.Error())
		return nil, status.Error(codes.Internal, "failed to generate uuid for new address record")
	}

	// create slug
	slug, err := uuid.NewRandom()
	if err != nil {
		log.Error(fmt.Sprintf("failed to generate slug for %s's new address record", req.GetUsername()), "err", err.Error())
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

	record := &sqlc.Address{
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

	// if request sets primary as true, validate there are no other primary address records for the user
	if req.GetIsPrimary() {
		primaryCount, err := as.addressStore.CountPrimaryAddresses(ctx, req.GetUsername())
		if err != nil {
			log.Error(fmt.Sprintf("failed to get primary address count for %s", req.GetUsername()), "err", err.Error())
			return nil, status.Error(codes.Internal, fmt.Sprintf("failed to get primary address count for %s", req.GetUsername()))
		}

		if primaryCount > 0 {
			log.Error(fmt.Sprintf("primary address record already exists for %s - primary count: %d", req.GetUsername(), primaryCount))
			return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("primary address record already exists for %s", req.GetUsername()))
		}

		record.IsPrimary = true
	} else {
		record.IsPrimary = false
	}

	// persist address record
	if err := as.addressStore.CreateAddress(ctx, record); err != nil {
		log.Error(fmt.Sprintf("failed to create address record for %s", req.GetUsername()), "err", err.Error())
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to create address record for %s", req.GetUsername()))
	}

	log.Info(fmt.Sprintf("successfuly persisted address record - slug %s for %s", slug, req.GetUsername()))

	// persist xref record
	if err := as.xrefStore.CreateProfileAddressXref(ctx, profile.Uuid, record.Uuid); err != nil {
		log.Error(fmt.Sprintf("failed to create address xref record for %s", req.GetUsername()), "err", err.Error())
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to create address xref record for %s", req.GetUsername()))
	}

	log.Info(fmt.Sprintf("succcessfully persisted profile-address record for %s and address - slug %s", req.GetUsername(), slug))

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
		IsCurrent:       record.IsCurrent,
		UpdatedAt:       timestamppb.New(record.UpdatedAt),
		CreatedAt:       timestamppb.New(record.CreatedAt),
	}, nil
}
