package phone

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	api "github.com/tdeslauriers/silhouette/api/v1"
	"github.com/tdeslauriers/silhouette/internal/auth"
	"github.com/tdeslauriers/silhouette/internal/storage/sql/sqlc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (ps *phoneServer) UpdatePhone(ctx context.Context, req *api.UpdatePhoneRequest) (*api.Phone, error) {

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

		// redundant, auth interceptor should deny this, but want
		// all logic for access expressed explicitly here
		if !authCtx.SelfAccessAllowed {
			log.Error("access denied: user does not have required scopes and self access is not allowed")
			return nil, status.Error(codes.PermissionDenied, "access denied")
		}

		// self access allowed, so requested username must == authenticated user's username
		if authCtx.UserClaims.Subject != strings.TrimSpace(req.GetUsername()) {
			log.Error("access denied", "err", "you may only edit a phone record for your own profile")
			return nil, status.Error(codes.PermissionDenied, "you may only edit a phone record for your own profile")
		}
	}

	// validate the command
	if err := ValidateCmd(req); err != nil {
		log.Error("invalid update phone request", "err", err.Error())
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	// do not need to fetch profile, auth validates user exists

	// get the existing phone record by slug
	phone, err := ps.phoneStore.GetPhone(ctx, req.PhoneSlug)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			log.Error(fmt.Sprintf("phone record not found for slug: %s", req.PhoneSlug), "err", err.Error())
			return nil, status.Error(codes.NotFound, fmt.Sprintf("phone record not found for slug: %s", req.PhoneSlug))
		} else {
			log.Error(fmt.Sprintf("failed to get phone record for slug %s", req.PhoneSlug), "err", err.Error())
			return nil, status.Error(codes.Internal, fmt.Sprintf("failed to get phone record for slug: %s", req.PhoneSlug))
		}
	}

	// prepare fields
	countryCode := strings.TrimSpace(req.GetCountryCode())
	phoneNumber := strings.TrimSpace(req.GetPhoneNumber())
	extension := strings.TrimSpace(req.GetExtension())
	phoneType := strings.TrimSpace(req.GetPhoneType().String())

	// check if update necessary
	if countryCode == phone.CountryCode.String &&
		phoneNumber == phone.PhoneNumber.String &&
		extension == phone.Extension.String &&
		phoneType == phone.PhoneType.String &&
		req.GetIsCurrent() == phone.IsCurrent {

		log.Warn(fmt.Sprintf("no update necessary, no changed to phone record for slug: %s", req.PhoneSlug))
		return &api.Phone{
			PhoneUuid:   phone.Uuid,
			Slug:        phone.Slug,
			CountryCode: phone.CountryCode.String,
			PhoneNumber: phone.PhoneNumber.String,
			Extension:   phone.Extension.String,
			PhoneType:   api.PhoneType(api.PhoneType_value[phone.PhoneType.String]),
			IsCurrent:   phone.IsCurrent,
			UpdatedAt:   timestamppb.New(phone.UpdatedAt),
			CreatedAt:   timestamppb.New(phone.CreatedAt),
		}, nil
	}

	// build updated record
	updated := &sqlc.Phone{
		Uuid: phone.Uuid,
		// Slug not needed for update
		// SlugIndex not needed for update
		CountryCode: sql.NullString{String: countryCode, Valid: countryCode != ""},
		PhoneNumber: sql.NullString{String: phoneNumber, Valid: phoneNumber != ""},
		Extension:   sql.NullString{String: extension, Valid: extension != ""},
		PhoneType:   sql.NullString{String: phoneType, Valid: phoneType != ""},
		IsCurrent:   req.GetIsCurrent(),
		UpdatedAt:   time.Now().UTC(),
		// CreatedAt not needed for update
	}

	// update persistence layer
	if err := ps.phoneStore.UpdatePhone(ctx, updated); err != nil {
		log.Error(fmt.Sprintf("failed to update phone record for slug %s", req.PhoneSlug), "err", err.Error())
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to update phone record for slug: %s", req.PhoneSlug))
	}

	// build audit log fields
	var updatedFields []any

	if countryCode != phone.CountryCode.String {
		updatedFields = append(updatedFields,
			slog.String("country_code_previous", phone.CountryCode.String),
			slog.String("country_code_updated", countryCode),
		)
	}

	if phoneNumber != phone.PhoneNumber.String {
		updatedFields = append(updatedFields,
			slog.String("phone_number_previous", phone.PhoneNumber.String),
			slog.String("phone_number_updated", phoneNumber),
		)
	}

	if extension != phone.Extension.String {
		updatedFields = append(updatedFields,
			slog.String("extension_previous", phone.Extension.String),
			slog.String("extension_updated", extension),
		)
	}

	if phoneType != phone.PhoneType.String {
		updatedFields = append(updatedFields,
			slog.String("phone_type_previous", phone.PhoneType.String),
			slog.String("phone_type_updated", phoneType),
		)
	}

	if req.GetIsCurrent() != phone.IsCurrent {
		updatedFields = append(updatedFields,
			slog.Bool("is_current_previous", phone.IsCurrent),
			slog.Bool("is_current_updated", req.GetIsCurrent()),
		)
	}

	// log successful update
	log.With(updatedFields...)
	log.Info(fmt.Sprintf("successfully updated phone record for slug: %s", req.PhoneSlug))

	return &api.Phone{
		PhoneUuid:   updated.Uuid,
		Slug:        updated.Slug,
		CountryCode: countryCode,
		PhoneNumber: phoneNumber,
		Extension:   extension,
		PhoneType:   api.PhoneType(api.PhoneType_value[phoneType]),
		IsCurrent:   updated.IsCurrent,
		UpdatedAt:   timestamppb.New(updated.UpdatedAt),
		CreatedAt:   timestamppb.New(phone.CreatedAt),
	}, nil
}
