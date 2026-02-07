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

	// add actors to audit log
	log = log.
		With("actor", authCtx.UserClaims.Subject).
		With("requesting_service", authCtx.SvcClaims.Subject)

	// map scopes from auth context
	userScopes := authCtx.UserClaims.MapScopes()
	isScoped := userScopes["w:silouhette:*"] || userScopes["w:silouhette:phone:*"]

	// if the user does not have any of the required scopes, self access must be allowed AND
	// requested username must match the authenticated user's username
	if !isScoped {

		// redundant, auth interceptor should deny this, but good practice
		if !authCtx.SelfAccessAllowed {
			log.Error("access denied: user does not have required scopes and self access is not allowed")
			return nil, status.Error(codes.PermissionDenied, "access denied")
		}

		// self access allowed, so requested username must == authenticated user's username
		if authCtx.UserClaims.Subject != strings.TrimSpace(req.GetUsername()) {
			log.Error("access denied", "err", "you may only create a phone record for your own profile")
			return nil, status.Error(codes.PermissionDenied, "you may only create a phone record for your own profile")
		}
	}

	// validate fields
	if err := ValidateCmd(req); err != nil {
		log.Error("failed to validate create phone command", "err", err.Error())
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	// get the profile record to validate user exists in service and
	// if so, retreive their record's uuid for xref
	profile, err := ps.profileStore.GetProfile(ctx, req.GetUsername())
	if err != nil {
		log.Error(fmt.Sprintf("failed to lookup profile for %s", req.GetUsername()), "err", err.Error())
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to look up profile for %s", req.GetUsername()))
	}

	// create phone record
	// generate uuid here so cross reference can be created
	id, err := uuid.NewRandom()
	if err != nil {
		log.Error(fmt.Sprintf("failed to generate uuid for %s's new phone record", req.GetUsername()), "err", err.Error())
		return nil, status.Error(codes.Internal, "failed to generate uuid for new phone record")
	}

	// generate slug
	slug, err := uuid.NewRandom()
	if err != nil {
		log.Error(fmt.Sprintf("failed to generate slug for %s's new phone record", req.GetUsername()), "err", err.Error())
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
		IsCurrent:   true, // a new phone record will default to current
		UpdatedAt:   now,
		CreatedAt:   now,
	}

	// persist phone record
	if err := ps.phoneStore.CreatePhone(ctx, record); err != nil {
		log.Error(fmt.Sprintf("failed to create phone record for %s", req.GetUsername()), "err", err.Error())
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to create phone record for %s", req.GetUsername()))
	}

	log.Info(fmt.Sprintf("successfully persisted phone record (slug %s) for %s", record.Slug, profile.Username))

	// persist profile-phone cross-reference
	if err := ps.xrefStore.CreateProfilePhoneXref(ctx, profile.Uuid, record.Slug); err != nil {
		log.Error(fmt.Sprintf("failed to create profile-phone cross-reference for %s", req.GetUsername()), "err", err.Error())
		return nil, status.Error(codes.Internal,
			fmt.Sprintf("failed to create profile-phone cross-reference for %s and phone (slug %s)", req.GetUsername(), record.Slug))
	}

	log.Info(
		fmt.Sprintf("successfully persisted profile-phone cross-reference for %s and phone (slug %s)", req.GetUsername(), record.Slug),
	)

	// return the created phone record
	return &api.Phone{
		PhoneUuid:   record.Uuid,
		Slug:        record.Slug,
		CountryCode: record.CountryCode.String,
		PhoneNumber: record.PhoneNumber.String,
		Extension:   proto.String(record.Extension.String),
		PhoneType:   ConvertPhoneType(record.PhoneType.String),
		IsCurrent:   record.IsCurrent,
		UpdatedAt:   timestamppb.New(record.UpdatedAt),
		CreatedAt:   timestamppb.New(record.CreatedAt),
	}, nil
}
