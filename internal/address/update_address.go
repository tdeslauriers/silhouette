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

	// add actors to audit log
	log = log.
		With("actor", authCtx.UserClaims.Subject).
		With("requesting_service", authCtx.SvcClaims.Subject)

	// map scopes from auth context
	userScopes := authCtx.UserClaims.MapScopes()
	isScoped := userScopes["w:silouhette:*"] || userScopes["w:silouhette:address:*"]

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
			log.Error("access denied: user does not have required scopes and requested username does not match authenticated user")
			return nil, status.Error(codes.PermissionDenied, "access denied")
		}
	}

	// validate request fields
	if err := ValidateCmd(req); err != nil {
		log.Error("invalid update address request", "err", err.Error())
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	// validate slug since not accounted for in cmd validation
	if !validate.IsValidUuid(strings.TrimSpace(req.GetSlug())) {
		log.Error("invalid address slug", "err", "address slug must be a valid UUID")
		return nil, status.Error(codes.InvalidArgument, "address slug must be a valid UUID")
	}

	// do not need to fetch the profile, auth validates user exists

	// get the existing record record by slug and username to
	// ensure the record exists and belongs to the requested user
	record, err := as.addressStore.GetAddress(ctx, req.GetSlug(), req.GetUsername())
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			log.Error(fmt.Sprintf("address slug %s record not found for user %s", req.GetSlug(), req.GetUsername()),
				"err", err.Error(),
			)
			return nil, status.Error(codes.NotFound, fmt.Sprintf("address record not found for slug: %s", req.GetSlug()))
		} else {
			log.Error(fmt.Sprintf("failed to get address record for slug %s", req.GetSlug()), "err", err.Error())
			return nil, status.Error(codes.Internal, fmt.Sprintf("failed to get address record for slug: %s", req.GetSlug()))
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
		req.GetIsCurrent() == record.IsCurrent {

		log.Warn(fmt.Sprintf("no update necessary, no changes to address record - slug: %s", req.GetSlug()))
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
		IsCurrent:    req.GetIsCurrent(),
		UpdatedAt:    time.Now().UTC(),
		// CreatedAt not needed for update
	}

	// update persistence layer
	if err := as.addressStore.UpdateAddress(ctx, updated); err != nil {
		log.Error(fmt.Sprintf("failed to update address record for slug %s", req.GetSlug()), "err", err.Error())
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to update address record - slug: %s", req.GetSlug()))
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

	// log the update
	log.Info(fmt.Sprintf("successfully updated address record - slug: %s", req.GetSlug()), updatedFields...)

	return &api.Address{
		Uuid:            record.Uuid,
		Slug:            record.Slug,
		StreetAddress:   updated.AddressLine1.String,
		StreetAddress_2: proto.String(updated.AddressLine2.String),
		City:            updated.City.String,
		StateProvince:   updated.State.String,
		PostalCode:      updated.Zip.String,
		Country:         updated.Country.String,
		IsCurrent:       updated.IsCurrent,
		CreatedAt:       timestamppb.New(record.CreatedAt),
		UpdatedAt:       timestamppb.New(updated.UpdatedAt),
	}, nil
}
