package profile

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

// CreateProfile creates a new profile record for a user in the database.
func (ps *profileServer) CreateProfile(ctx context.Context, req *api.CreateProfileRequest) (*api.Profile, error) {

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

	// add s2s to audit log
	log = log.With("requesting_service", authCtx.SvcClaims.Subject)

	// validate fields
	if err := ValidateCmd(req); err != nil {
		log.Error("invalid create-profile request", "err", err.Error())
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	// check to see if profile already exists for the user, and return an error if it does since
	// don't want to allow multiple profiles per user
	_, err = ps.profileStore.GetProfile(ctx, req.GetUsername())
	if err == nil {
		log.Error("profile already exists for user", "username", req.GetUsername())
		return nil, status.Error(codes.AlreadyExists, fmt.Sprintf("profile %s already exists for user", strings.TrimSpace(req.GetUsername())))
	}

	// build profile record
	id, err := uuid.NewRandom()
	if err != nil {
		log.Error("failed to generate profile ID", "err", err.Error())
		return nil, status.Error(codes.Internal, "failed to generate profile ID")
	}

	// build record
	now := time.Now().UTC()

	record := &sqlc.Profile{
		Uuid:     id.String(),
		Username: strings.TrimSpace(req.GetUsername()),
		NickName: sql.NullString{
			String: strings.TrimSpace(req.GetNickName()),
			Valid:  len(strings.TrimSpace(req.GetNickName())) > 0,
		},
		DarkMode:  true, // default since there is no light mode rn
		CreatedAt: now,
		UpdatedAt: now,
	}

	// persist profile record
	if err := ps.profileStore.CreateProfile(ctx, record); err != nil {
		log.Error("failed to create profile record", "err", err.Error())
		return nil, status.Error(codes.Internal, "failed to create profile record")
	}

	// log success
	log.Info(fmt.Sprintf("successfully created new profile record for %s", req.GetUsername()))

	// build response
	return &api.Profile{
		Username:  record.Username,
		NickName:  proto.String(record.NickName.String),
		DarkMode:  record.DarkMode,
		UpdatedAt: timestamppb.New(record.UpdatedAt),
		CreatedAt: timestamppb.New(record.CreatedAt),
	}, nil
}
