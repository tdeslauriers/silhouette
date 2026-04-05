package phone

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

// CreatePhone creates a new phone record for a user in the database.
func (ps *phoneServer) CreatePhone(ctx context.Context, req *api.CreatePhoneRequest) (*api.Phone, error) {

	// get telemetry context
	telemetry, ok := exo.GetTelemetryFromContext(ctx)
	if !ok {
		// this should not be possible since the interceptor will have generated new if missing
		ps.logger.Warn("failed to get telmetry from incoming context")
	}

	// append telemetry fields
	log := ps.logger.With(telemetry.TelemetryFields()...)

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
		log.Error("failed to validate create phone command", "err", err.Error())
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	// get the profile record to validate user exists in service and
	// if so, retreive their record's uuid for xref
	profile, err := ps.profileStore.GetProfile(ctx, username)
	if err != nil {
		log.Error(fmt.Sprintf("failed to lookup profile for %s", username), "err", err.Error())
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to look up profile for %s", username))
	}

	// count of how many phone records exist for the user
	phoneCount, err := ps.phoneStore.CountPhones(ctx, username)
	if err != nil {
		log.Error(fmt.Sprintf("failed to get phone count for %s", username), "err", err.Error())
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to get phone count for %s", username))
	}

	if phoneCount >= 3 {
		log.Error(fmt.Sprintf("phone record count for %s is %d - cannot create more than 3 phone records per user", username, phoneCount))
		return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("phone record count for %s is %d - cannot create more than 3 phone records per user", username, phoneCount))
	}

	// create phone record
	// generate uuid here so cross reference can be created
	id, err := uuid.NewRandom()
	if err != nil {
		log.Error(fmt.Sprintf("failed to generate uuid for %s's new phone record", username), "err", err.Error())
		return nil, status.Error(codes.Internal, "failed to generate uuid for new phone record")
	}

	// generate slug
	slug, err := uuid.NewRandom()
	if err != nil {
		log.Error(fmt.Sprintf("failed to generate slug for %s's new phone record", username), "err", err.Error())
		return nil, status.Error(codes.Internal, "failed to generate slug for new phone record")
	}

	// generate timestamp
	now := time.Now().UTC()

	// prepare fields
	countryCode := normalizeCountryCode(strings.TrimSpace(req.GetCountryCode()))
	phoneNumber := normalizePhoneNumber(strings.TrimSpace(req.GetPhoneNumber()))
	phoneType := strings.TrimSpace(req.GetPhoneType().String())

	var extension string
	if len(req.GetExtension()) > 0 {
		extension = normalizeExtension(strings.TrimSpace(req.GetExtension()))
	}

	record := &sqlc.Phone{
		Uuid:        id.String(),
		Slug:        slug.String(),
		CountryCode: sql.NullString{String: countryCode, Valid: true},
		PhoneNumber: sql.NullString{String: phoneNumber, Valid: true},
		Extension:   sql.NullString{String: extension, Valid: extension != ""},
		PhoneType:   sql.NullString{String: phoneType, Valid: true},
		IsCurrent:   req.GetIsCurrent(),
		UpdatedAt:   now,
		CreatedAt:   now,
	}

	// if request sets primary as true, validate there are no other primary phone records for the user
	switch {
	case !record.IsCurrent && !req.GetIsPrimary():
		// do nothing - this is valid
		record.IsPrimary = false
	case !record.IsCurrent && req.GetIsPrimary():
		// cannot create a non current record as primary - this is invalid
		log.Error(fmt.Sprintf("invalid phone record for user %s - non-current record cannot be primary during creation", username))
		return nil, status.Error(codes.InvalidArgument, "invalid phone record - non-current record cannot be primary")
	case record.IsCurrent && req.GetIsPrimary():
		// user should not have current primary phone records

		// get count of how many primary phone records exist for the user
		count, err := ps.phoneStore.CountPrimaryPhones(ctx, username)
		if err != nil {
			log.Error(fmt.Sprintf("failed to get primary phone count for %s", username), "err", err.Error())
			return nil, status.Error(codes.Internal, fmt.Sprintf("failed to get primary phone count for %s", username))
		}

		if count > 0 {
			log.Error(fmt.Sprintf("primary phone record already exists for %s - cannot create another primary record", username))
			return nil, status.Error(codes.InvalidArgument, "primary phone record already exists - cannot create another primary record")
		}

		record.IsPrimary = true
	}

	// persist phone record
	if err := ps.phoneStore.CreatePhone(ctx, record); err != nil {
		log.Error(fmt.Sprintf("failed to create phone record for %s", username), "err", err.Error())
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to create phone record for %s", username))
	}

	log.Info(fmt.Sprintf("successfully persisted phone record (slug %s) for %s", slug, profile.Username))

	// persist profile-phone cross-reference
	if err := ps.xrefStore.CreateProfilePhoneXref(ctx, profile.Uuid, id.String()); err != nil {
		log.Error(fmt.Sprintf("failed to create profile-phone cross-reference for %s", username), "err", err.Error())
		return nil, status.Error(codes.Internal,
			fmt.Sprintf("failed to create profile-phone cross-reference for %s and phone (slug %s)", username, slug))
	}

	log.Info(
		fmt.Sprintf("successfully persisted profile-phone cross-reference for %s and phone (slug %s)", username, slug),
	)

	// return the created phone record
	// NOTE: cant return record because the model is encrypted on save.
	return &api.Phone{
		PhoneUuid:   id.String(),
		Slug:        slug.String(),
		CountryCode: countryCode,
		PhoneNumber: phoneNumber,
		Extension:   proto.String(extension),
		PhoneType:   ConvertPhoneType(phoneType),
		IsCurrent:   record.IsCurrent,
		UpdatedAt:   timestamppb.New(record.UpdatedAt),
		CreatedAt:   timestamppb.New(record.CreatedAt),
	}, nil
}
