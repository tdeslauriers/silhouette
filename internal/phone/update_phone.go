package phone

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	exo "github.com/tdeslauriers/carapace/pkg/connect/grpc"
	"github.com/tdeslauriers/carapace/pkg/validate"
	api "github.com/tdeslauriers/silhouette/api/v1"
	"github.com/tdeslauriers/silhouette/internal/auth"
	"github.com/tdeslauriers/silhouette/internal/storage/sql/sqlc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// UpdatePhone updates an existing phone record for a user in the database.
func (ps *phoneServer) UpdatePhone(ctx context.Context, req *api.UpdatePhoneRequest) (*api.Phone, error) {

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

	// validate slug since not accounted for in cmd validation
	if !validate.IsValidUuid(strings.TrimSpace(req.GetPhoneSlug())) {
		log.Error("invalid phone slug", "err", "phone slug must be a valid UUID")
		return nil, status.Error(codes.InvalidArgument, "phone slug must be a valid UUID")
	}

	// do not need to fetch profile, auth validates user exists

	// get the existing record record by slug and username
	// a record update requires the cmd to have the correct slug and
	// the correct username associated with the record record
	record, err := ps.phoneStore.GetUsersPhone(ctx, req.GetPhoneSlug(), req.GetUsername())
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			log.Error(
				fmt.Sprintf("phone slug %s record not found for user %s", req.GetPhoneSlug(), req.GetUsername()),
				"err", err.Error(),
			)
			return nil, status.Error(codes.NotFound, fmt.Sprintf("phone record not found for slug: %s", req.GetPhoneSlug()))
		} else {
			log.Error(fmt.Sprintf("failed to get phone record for slug %s", req.GetPhoneSlug()), "err", err.Error())
			return nil, status.Error(codes.Internal, fmt.Sprintf("failed to get phone record for slug: %s", req.GetPhoneSlug()))
		}
	}

	// prepare fields
	countryCode := normalizeCountryCode(strings.TrimSpace(req.GetCountryCode()))
	phoneNumber := normalizePhoneNumber(strings.TrimSpace(req.GetPhoneNumber()))
	phoneType := strings.TrimSpace(req.GetPhoneType().String())

	var extension string
	if len(req.GetExtension()) > 0 {
		extension = normalizeExtension(strings.TrimSpace(req.GetExtension()))
	}

	// check if update necessary
	if countryCode == record.CountryCode.String &&
		phoneNumber == record.PhoneNumber.String &&
		extension == record.Extension.String &&
		phoneType == record.PhoneType.String &&
		req.GetIsCurrent() == record.IsCurrent {

		log.Warn(fmt.Sprintf("no update necessary, no changed to phone record - slug: %s", req.GetPhoneSlug()))
		return &api.Phone{
			Uuid:        record.Uuid,
			Slug:        record.Slug,
			CountryCode: record.CountryCode.String,
			PhoneNumber: record.PhoneNumber.String,
			Extension:   proto.String(record.Extension.String),
			PhoneType:   api.PhoneType(api.PhoneType_value[record.PhoneType.String]),
			IsCurrent:   record.IsCurrent,
			UpdatedAt:   timestamppb.New(record.UpdatedAt),
			CreatedAt:   timestamppb.New(record.CreatedAt),
		}, nil
	}

	// build updated record
	updated := &sqlc.Phone{
		Uuid: record.Uuid,
		Slug: record.Slug,
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
		log.Error(fmt.Sprintf("failed to update phone record for slug %s", req.GetPhoneSlug()), "err", err.Error())
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to update phone record - slug: %s", req.GetPhoneSlug()))
	}

	// build audit log fields
	var updatedFields []any

	if countryCode != record.CountryCode.String {
		updatedFields = append(updatedFields,
			slog.String("country_code_previous", record.CountryCode.String),
			slog.String("country_code_updated", countryCode),
		)
	}

	if phoneNumber != record.PhoneNumber.String {
		updatedFields = append(updatedFields,
			slog.String("phone_number_previous", record.PhoneNumber.String),
			slog.String("phone_number_updated", phoneNumber),
		)
	}

	if extension != record.Extension.String {
		updatedFields = append(updatedFields,
			slog.String("extension_previous", record.Extension.String),
			slog.String("extension_updated", extension),
		)
	}

	if phoneType != record.PhoneType.String {
		updatedFields = append(updatedFields,
			slog.String("phone_type_previous", record.PhoneType.String),
			slog.String("phone_type_updated", phoneType),
		)
	}

	if req.GetIsCurrent() != record.IsCurrent {
		updatedFields = append(updatedFields,
			slog.Bool("is_current_previous", record.IsCurrent),
			slog.Bool("is_current_updated", req.GetIsCurrent()),
		)
	}

	// log successful update
	log.With(updatedFields...)
	log.Info(fmt.Sprintf("successfully updated phone record - slug: %s", req.GetPhoneSlug()))

	return &api.Phone{
		Uuid:        record.Uuid,
		Slug:        record.Slug,
		CountryCode: countryCode,
		PhoneNumber: phoneNumber,
		Extension:   proto.String(extension),
		PhoneType:   api.PhoneType(api.PhoneType_value[phoneType]),
		IsCurrent:   updated.IsCurrent,
		UpdatedAt:   timestamppb.New(updated.UpdatedAt),
		CreatedAt:   timestamppb.New(record.CreatedAt),
	}, nil
}
