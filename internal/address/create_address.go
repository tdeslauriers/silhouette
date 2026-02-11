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

	// create address record
	id, err := uuid.NewRandom()
	if err != nil {
		log.Error(fmt.Sprintf("failed to generate uuid for %s's new address record", req.GetUsername()), "err", err.Error())
		return nil, status.Error(codes.Internal, "failed to generate uuid for new address record")
	}

	now := time.Now().UTC()

	record := &sqlc.Address{
		Uuid:         id.String(),
		Slug:         id.String(),
		AddressLine1: sql.NullString{String: strings.TrimSpace(req.GetStreetAddress()), Valid: true},
		AddressLine2: sql.NullString{
			String: strings.TrimSpace(req.GetStreetAddress_2()),
			Valid:  req.GetStreetAddress_2() != "",
		},
		City:      sql.NullString{String: strings.TrimSpace(req.GetCity()), Valid: true},
		State:     sql.NullString{String: strings.TrimSpace(req.GetStateProvince()), Valid: true},
		Zip:       sql.NullString{String: strings.TrimSpace(req.GetPostalCode()), Valid: true},
		Country:   sql.NullString{String: strings.TrimSpace(req.GetCountry()), Valid: true},
		IsCurrent: true,
		UpdatedAt: now,
		CreatedAt: now,
	}

	// persist address record
	if err := as.addressStore.CreateAddress(ctx, record); err != nil {
		log.Error(fmt.Sprintf("failed to create address record for %s", req.GetUsername()), "err", err.Error())
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to create address record for %s", req.GetUsername()))
	}

	log.Info(fmt.Sprintf("successfuly persisted address record - slug %s for %s", record.Slug, req.GetUsername()))

	// persist xref record
	if err := as.xrefStore.CreateProfileAddressXref(ctx, profile.Uuid, record.Uuid); err != nil {
		log.Error(fmt.Sprintf("failed to create address xref record for %s", req.GetUsername()), "err", err.Error())
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to create address xref record for %s", req.GetUsername()))
	}

	log.Info(fmt.Sprintf("succcessfully persisted profile-address record for %s and address - slug %s", req.GetUsername(), record.Slug))

	// return the created address record
	return &api.Address{
		AddressUuid:     record.Uuid,
		Slug:            record.Slug,
		StreetAddress:   record.AddressLine1.String,
		StreetAddress_2: proto.String(record.AddressLine2.String),
		City:            record.City.String,
		StateProvince:   record.State.String,
		PostalCode:      record.Zip.String,
		Country:         record.Country.String,
		IsCurrent:       record.IsCurrent,
		UpdatedAt:       timestamppb.New(record.UpdatedAt),
		CreatedAt:       timestamppb.New(record.CreatedAt),
	}, nil
}
