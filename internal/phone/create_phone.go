package phone

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	api "github.com/tdeslauriers/silhouette/api/v1"
	"github.com/tdeslauriers/silhouette/internal/auth"
	"github.com/tdeslauriers/silhouette/internal/storage/sql/sqlc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// CreatePhone creates a new phone record for a user in the database.
func (ps *phoneServer) CreatePhone(ctx context.Context, req *api.CreatePhoneRequest) (*api.Phone, error) {

	// get authz context
	authCtx, err := auth.GetAuthContext(ctx)
	if err != nil {
		ps.logger.Error("failed to get auth context", "err", err.Error())
		return nil, status.Error(codes.Unauthenticated, "failed to get auth context")
	}

	// add actors to audit log
	log := ps.logger.
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

	// get the profile record to validate user exists and
	// if so, retreive their record's uuid for xref
	profile, err := ps.profileStore.GetProfile(ctx, req.Username)
	if err != nil {
		log.Error(fmt.Sprintf("failed to lookup profile for %s", req.Username), "err", err.Error())
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to look up profile for %s", req.Username))
	}

	// create phone record
	// generate uuid here so cross reference can be created
	id, err := uuid.NewRandom()
	if err != nil {
		log.Error(fmt.Sprintf("failed to generate uuid for %s's new phone record", req.Username), "err", err.Error())
		return nil, status.Error(codes.Internal, "failed to generate uuid for new phone record")
	}

	// generate timestamp
	now := time.Now().UTC()

	record := &sqlc.Phone{
		Uuid:        id.String(),
		CountryCode: sql.NullString{String: normalizeCountryCode(req.GetCountryCode()), Valid: true},
		PhoneNumber: sql.NullString{String: normalizePhoneNumber(req.GetPhoneNumber()), Valid: true},
		Extension:   sql.NullString{String: normalizeExtension(req.GetExtension()), Valid: true},
		PhoneType:   sql.NullString{String: convertToSqlString(req.GetPhoneType()), Valid: true},
		IsCurrent:   true, // a new phone record will default to current
		UpdatedAt:   now,
		CreatedAt:   now,
	}

	// persist phone record
	if err := ps.phoneStore.CreatePhone(ctx, record); err != nil {
		log.Error(fmt.Sprintf("failed to create phone record for %s", req.Username), "err", err.Error())
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to create phone record for %s", req.Username))
	}

	log.Info(fmt.Sprintf("successfully persisted phone record %s for %s", record.Uuid, profile.Username))

	// persist profile-phone cross-reference
	if err := ps.xrefStore.CreateProfilePhoneXref(ctx, profile.Uuid, record.Uuid); err != nil {
		log.Error(fmt.Sprintf("failed to create profile-phone cross-reference for %s", req.Username), "err", err.Error())
		return nil, status.Error(codes.Internal,
			fmt.Sprintf("failed to create profile-phone cross-reference for %s and phone %s", req.Username, record.Uuid))
	}

	log.Info(
		fmt.Sprintf("successfully created profile-phone cross-reference for %s and phone %s", req.Username, record.Uuid),
	)

	// return the created phone record
	return &api.Phone{
		PhoneUuid:   record.Uuid,
		CountryCode: record.CountryCode.String,
		PhoneNumber: record.PhoneNumber.String,
		Extension:   record.Extension.String,
		PhoneType:   ConvertPhoneType(record.PhoneType.String),
		IsCurrent:   record.IsCurrent,
		UpdatedAt:   timestamppb.New(record.UpdatedAt),
		CreatedAt:   timestamppb.New(record.CreatedAt),
	}, nil

}
