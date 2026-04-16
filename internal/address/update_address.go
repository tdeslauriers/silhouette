package address

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

// UpdateAddress updates an existing address record for a user in the database.
func (as *addressServer) UpdateAddress(ctx context.Context, req *api.UpdateAddressRequest) (*api.Address, error) {

	// get telemetry context
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

	// prepare username and slug parameter fields
	username := strings.TrimSpace(req.GetUsername())
	slug := strings.TrimSpace(req.GetSlug())

	// authorize the request
	if err := auth.AuthorizeRequest(authCtx, username); err != nil {
		log.Error("failed to authorize request", "err", err.Error())
		return nil, status.Error(codes.PermissionDenied, "access denied")
	}

	// validate request fields
	if err := ValidateCmd(req); err != nil {
		log.Error("invalid update address request", "err", err.Error())
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	// validate slug since not accounted for in cmd validation
	if err := validate.ValidateUuid(slug); err != nil {
		log.Error("invalid address slug", "err", "address slug must be a valid UUID")
		return nil, status.Error(codes.InvalidArgument, "address slug must be a valid UUID")
	}

	// get the existing record record by slug and username to
	// ensure the record exists and belongs to the requested user
	record, err := as.addressStore.GetAddress(ctx, slug, username)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			log.Error(fmt.Sprintf("address slug %s record not found for user %s", slug, username),
				"err", err.Error(),
			)
			return nil, status.Error(codes.NotFound, fmt.Sprintf("address record not found for slug: %s", slug))
		} else {
			log.Error(fmt.Sprintf("failed to get address record for slug %s", slug), "err", err.Error())
			return nil, status.Error(codes.Internal, fmt.Sprintf("failed to get address record for slug: %s", slug))
		}
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

	// check if update necessary
	if streetAddress == record.AddressLine1.String &&
		streetAddress_2 == record.AddressLine2.String &&
		city == record.City.String &&
		stateProvince == record.State.String &&
		postalCode == record.Zip.String &&
		country == record.Country.String &&
		req.GetIsCurrent() == record.IsCurrent &&
		req.GetIsPrimary() == record.IsPrimary {

		log.Warn(fmt.Sprintf("no update necessary, no changes to address record - slug: %s", slug))
		return &api.Address{
			Uuid:            record.Uuid,
			Slug:            record.Slug,
			StreetAddress:   record.AddressLine1.String,
			StreetAddress_2: proto.String(record.AddressLine2.String),
			City:            record.City.String,
			StateProvince:   record.State.String,
			PostalCode:      record.Zip.String,
			Country:         record.Country.String,
			IsCurrent:       record.IsCurrent,
			IsPrimary:       record.IsPrimary,
			CreatedAt:       timestamppb.New(record.CreatedAt),
			UpdatedAt:       timestamppb.New(record.UpdatedAt),
		}, nil
	}

	// build updated record
	updated := &sqlc.Address{
		Uuid: record.Uuid,
		Slug: record.Slug,
		// SlugIndex not needed for update
		AddressLine1: sql.NullString{String: streetAddress, Valid: streetAddress != ""},
		AddressLine2: sql.NullString{String: streetAddress_2, Valid: streetAddress_2 != ""},
		City:         sql.NullString{String: city, Valid: city != ""},
		State:        sql.NullString{String: stateProvince, Valid: stateProvince != ""},
		Zip:          sql.NullString{String: postalCode, Valid: postalCode != ""},
		Country:      sql.NullString{String: country, Valid: country != ""},
		IsCurrent:    req.GetIsCurrent(), // final state is checked below is_primary validation
		UpdatedAt:    time.Now().UTC(),
		// CreatedAt not needed for update
	}

	// if request sets primary as true and record is not currently primary,
	// validate there are no other primary address records for the user
	switch {
	case req.GetIsPrimary() && record.IsPrimary:
		// do nothing - record is already primary and remains primary
		updated.IsPrimary = true
	case !req.GetIsPrimary() && !record.IsPrimary:
		// do nothing - record is not primary and remains non-primary
		updated.IsPrimary = false
	case !req.GetIsPrimary() && record.IsPrimary:
		// if primary is being removed, set to false, this
		// is allowed without validation since user can have multiple non-primary records
		updated.IsPrimary = false
	case req.GetIsPrimary() && !record.IsPrimary:

		count, err := as.addressStore.CountPrimaryAddresses(ctx, username)
		if err != nil {
			log.Error(fmt.Sprintf("failed to get primary address count for user %s during update of slug %s", username, slug), "err", err.Error())
			return nil, status.Error(codes.Internal, fmt.Sprintf("failed to get primary address count for user %s during update of slug %s", username, slug))
		}

		if count > 0 {
			log.Error(fmt.Sprintf("primary address record already exists for user %s - cannot update slug %s to primary", username, slug))
			return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("primary address record already exists for user %s - cannot update slug %s to primary", username, slug))
		}

		updated.IsPrimary = true
	}

	// validate the final post-update state since a record can only be non-current
	// when it is also non-primary
	if updated.IsPrimary && !updated.IsCurrent {
		log.Error(fmt.Sprintf("invalid update request for slug %s - primary address records must be current", slug))
		return nil, status.Error(codes.InvalidArgument, "primary address records must be current")
	}

	// update persistence layer
	if err := as.addressStore.UpdateAddress(ctx, updated); err != nil {
		log.Error(fmt.Sprintf("failed to update address record for slug %s", slug), "err", err.Error())
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to update address record - slug: %s", slug))
	}

	// build audit log fields
	var updatedFields []any

	if streetAddress != record.AddressLine1.String {
		updatedFields = append(updatedFields,
			slog.String("street_address_previous", record.AddressLine1.String),
			slog.String("street_address_updated", streetAddress),
		)
	}

	if streetAddress_2 != record.AddressLine2.String {
		updatedFields = append(updatedFields,
			slog.String("street_address_2_previous", record.AddressLine2.String),
			slog.String("street_address_2_updated", streetAddress_2),
		)
	}

	if city != record.City.String {
		updatedFields = append(updatedFields,
			slog.String("city_previous", record.City.String),
			slog.String("city_updated", city),
		)
	}

	if stateProvince != record.State.String {
		updatedFields = append(updatedFields,
			slog.String("state_province_previous", record.State.String),
			slog.String("state_province_updated", stateProvince),
		)
	}

	if postalCode != record.Zip.String {
		updatedFields = append(updatedFields,
			slog.String("postal_code_previous", record.Zip.String),
			slog.String("postal_code_updated", postalCode),
		)
	}

	if country != record.Country.String {
		updatedFields = append(updatedFields,
			slog.String("country_previous", record.Country.String),
			slog.String("country_updated", country),
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

	// log the update
	log.Info(fmt.Sprintf("successfully updated address record - slug: %s", slug), updatedFields...)

	return &api.Address{
		Uuid:            record.Uuid,
		Slug:            record.Slug,
		StreetAddress:   streetAddress,
		StreetAddress_2: proto.String(streetAddress_2),
		City:            city,
		StateProvince:   stateProvince,
		PostalCode:      postalCode,
		Country:         country,
		IsCurrent:       updated.IsCurrent,
		IsPrimary:       updated.IsPrimary,
		CreatedAt:       timestamppb.New(record.CreatedAt),
		UpdatedAt:       timestamppb.New(updated.UpdatedAt),
	}, nil
}
