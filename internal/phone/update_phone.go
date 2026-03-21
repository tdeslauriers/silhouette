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

		// clean up request fields for use
	username := strings.TrimSpace(req.GetUsername())
	slug := strings.TrimSpace(req.GetPhoneSlug())

	// authorize the request
	if err := auth.AuthorizeRequest(authCtx, username); err != nil {
		log.Error("failed to authorize request", "err", err.Error())
		return nil, status.Error(codes.PermissionDenied, "access denied")
	}

	// validate the command
	if err := ValidateCmd(req); err != nil {
		log.Error("invalid update phone request", "err", err.Error())
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	// validate slug since not accounted for in cmd validation
	if !validate.IsValidUuid(strings.TrimSpace(slug)) {
		log.Error("invalid phone slug", "err", "phone slug must be a valid UUID")
		return nil, status.Error(codes.InvalidArgument, "phone slug must be a valid UUID")
	}

	// get the existing record record by slug and username
	// a record update requires the cmd to have the correct slug and
	// the correct username associated with the record record
	record, err := ps.phoneStore.GetPhone(ctx, slug, username)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			log.Error(
				fmt.Sprintf("phone slug %s record not found for user %s", slug, username),
				"err", err.Error(),
			)
			return nil, status.Error(codes.NotFound, fmt.Sprintf("phone record not found for slug: %s", slug))
		} else {
			log.Error(fmt.Sprintf("failed to get phone record for slug %s", slug), "err", err.Error())
			return nil, status.Error(codes.Internal, fmt.Sprintf("failed to get phone record for slug: %s", slug))
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
		req.GetIsCurrent() == record.IsCurrent &&
		req.GetIsPrimary() == record.IsPrimary {

		log.Warn(fmt.Sprintf("no update necessary, no changed to phone record - slug: %s", slug))
		return &api.Phone{
			Uuid:        record.Uuid,
			Slug:        record.Slug,
			CountryCode: record.CountryCode.String,
			PhoneNumber: record.PhoneNumber.String,
			Extension:   proto.String(record.Extension.String),
			PhoneType:   api.PhoneType(api.PhoneType_value[record.PhoneType.String]),
			IsCurrent:   record.IsCurrent,
			IsPrimary:   record.IsPrimary,
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
		IsCurrent:   req.GetIsCurrent(), // final state is checked below is_primary validation
		UpdatedAt:   time.Now().UTC(),
		// IsPrimary handled below since need to validate primary phone count if setting to true
		// CreatedAt not needed for update
	}

	// if request sets primary as true, validate there are no other primary phone records for the user
	switch {
	case req.GetIsPrimary() && record.IsPrimary:
		// do nothing - record is already primary and remains primary
		updated.IsPrimary = true
	case !req.GetIsPrimary() && !record.IsPrimary:
		// do nothing - record is already non-primary and remains non-primary
		updated.IsPrimary = false
	case !req.GetIsPrimary() && record.IsPrimary:
		// if primary is being removed, simply set to false - user can have multiple non-primary records
		updated.IsPrimary = false
	case req.GetIsPrimary() && !record.IsPrimary:
		// if primary is being added, need to validate there are no other primary records for the user
		phones, err := ps.phoneStore.GetPhonesByUser(ctx, username)
		if err != nil {
			log.Error(fmt.Sprintf("failed to get phone records for user %s during primary phone update validation", username), "err", err.Error())
			return nil, status.Error(codes.Internal, fmt.Sprintf("failed to get phone records for user %s during primary phone update validation", username))
		}

		// error if no phones found should not be possible since the record being updated belongs to the user, but handle just in case
		if len(phones) < 1 {
			log.Error(fmt.Sprintf("no phone records found for user %s during primary phone update validation", username))
			return nil, status.Error(codes.Internal, fmt.Sprintf("no phone records found for user %s during primary phone update validation", username))
		}

		// if there is only one record then it can be made primary without validation
		// Still: sanity check to make sure the slugs match before updating
		if len(phones) == 1 {
			if phones[0].Slug != slug {
				log.Error(fmt.Sprintf("phone slug %s record not found for user %s during primary phone update validation", slug, username))
				return nil, status.Error(codes.NotFound, fmt.Sprintf("phone record not found for slug: %s during primary phone update validation", slug))
			}
			updated.IsPrimary = true
			break
		}

		// loop thru phone records to validate no other primary records exist for the user
		for _, p := range phones {
			if p.IsPrimary && p.Slug != slug {
				log.Error(fmt.Sprintf("primary phone record already exists for user %s during primary phone update validation - slug: %s", username, p.Slug))
				return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("primary phone record already exists for user %s during primary phone update validation", username))
			}
		}

		updated.IsPrimary = true
	}

	// sanity check: ensure final state does not include primary == true and is_current == false - this is invalid
	if updated.IsPrimary && !updated.IsCurrent {
		log.Error(fmt.Sprintf("invalid phone record for user %s - non-current record cannot be primary during update", username))
		return nil, status.Error(codes.InvalidArgument, "invalid phone record - non-current record cannot be primary")
	}

	// update persistence layer
	if err := ps.phoneStore.UpdatePhone(ctx, updated); err != nil {
		log.Error(fmt.Sprintf("failed to update phone record for slug %s", slug), "err", err.Error())
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to update phone record - slug: %s", slug))
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

	if req.GetIsPrimary() != record.IsPrimary {
		updatedFields = append(updatedFields,
			slog.Bool("is_primary_previous", record.IsPrimary),
			slog.Bool("is_primary_updated", req.GetIsPrimary()),
		)
	}

	// log successful update
	log = log.With(updatedFields...)
	log.Info(fmt.Sprintf("successfully updated phone record - slug: %s", slug))

	return &api.Phone{
		Uuid:        record.Uuid,
		Slug:        record.Slug,
		CountryCode: countryCode,
		PhoneNumber: phoneNumber,
		Extension:   proto.String(extension),
		PhoneType:   api.PhoneType(api.PhoneType_value[phoneType]),
		IsCurrent:   updated.IsCurrent,
		IsPrimary:   updated.IsPrimary,
		UpdatedAt:   timestamppb.New(updated.UpdatedAt),
		CreatedAt:   timestamppb.New(record.CreatedAt),
	}, nil
}
