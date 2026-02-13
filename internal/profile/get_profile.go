package profile

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	exo "github.com/tdeslauriers/carapace/pkg/connect/grpc"
	api "github.com/tdeslauriers/silhouette/api/v1"
	"github.com/tdeslauriers/silhouette/internal/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// GetProfile retrieves a user profile by username, returning
// the profile information including address and phone details.
func (s *profileServer) GetProfile(ctx context.Context, req *api.GetProfileRequest) (*api.Profile, error) {

	// get telemetry context
	telemetry, ok := exo.GetTelemetryFromContext(ctx)
	if !ok {
		// this should not be possible since the interceptor will have generated new if missing
		s.logger.Warn("failed to get telmetry from incoming context")
	}

	// append telemetry fields
	log := s.logger.With(telemetry.TelemetryFields()...)

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

	// get the profile record by username
	record, err := s.profileStore.GetCompleteProfile(ctx, req.GetUsername())
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			log.Error(fmt.Sprintf("profile record not found for %s", req.GetUsername()))
			return nil, status.Error(codes.NotFound, "profile record not found")
		} else {
			log.Error("failed to get profile record", "err", err.Error())
			return nil, status.Error(codes.Internal, "failed to get profile record")
		}
	}

	// build the response profile record
	profile := &api.Profile{
		Uuid:      record.Profile.Uuid,
		Username:  record.Profile.Username,
		NickName:  proto.String(record.Profile.NickName.String),
		DarkMode:  record.Profile.DarkMode,
		UpdatedAt: timestamppb.New(record.Profile.UpdatedAt),
		CreatedAt: timestamppb.New(record.Profile.CreatedAt),
	}

	// convert the address records to the api type
	addresses := make([]*api.Address, 0, len(record.Addresses))
	for _, address := range record.Addresses {
		addresses = append(addresses, &api.Address{
			Uuid:            address.Uuid,
			Slug:            address.Slug,
			StreetAddress:   address.AddressLine1.String,
			StreetAddress_2: proto.String(address.AddressLine2.String),
			City:            address.City.String,
			StateProvince:   address.State.String,
			PostalCode:      address.Zip.String,
			Country:         address.Country.String,
			UpdatedAt:       timestamppb.New(address.UpdatedAt),
			CreatedAt:       timestamppb.New(address.CreatedAt),
		})
	}

	// assign the converted addresses to profile response
	if len(addresses) > 0 {
		profile.Address = addresses
	}

	// convert the phone records to the api type
	phones := make([]*api.Phone, 0, len(record.Phones))
	for _, phone := range record.Phones {
		phones = append(phones, &api.Phone{
			Uuid:        phone.Uuid,
			Slug:        phone.Slug,
			CountryCode: phone.CountryCode.String,
			PhoneNumber: phone.PhoneNumber.String,
			Extension:   proto.String(phone.Extension.String),
			PhoneType:   api.PhoneType(api.PhoneType_value[phone.PhoneType.String]),
			IsCurrent:   phone.IsCurrent,
			UpdatedAt:   timestamppb.New(phone.UpdatedAt),
			CreatedAt:   timestamppb.New(phone.CreatedAt),
		})
	}

	// assign the converted phones to profile response
	if len(phones) > 0 {
		profile.Phone = phones
	}

	log.Info(fmt.Sprintf("successfully retrieved %s profile record", req.GetUsername()))

	return profile, nil
}
