package profile

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	exo "github.com/tdeslauriers/carapace/pkg/connect/grpc"
	api "github.com/tdeslauriers/silhouette/api/v1"
	"github.com/tdeslauriers/silhouette/internal/auth"
	"github.com/tdeslauriers/silhouette/internal/storage/sql/sqlc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// UpdateProfile updates an existing profile record for a user in the database.
func (ps *profileServer) UpdateProfile(ctx context.Context, req *api.UpdateProfileRequest) (*api.Profile, error) {

	// get telemetry from context
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

	// authorize the request
	if err := auth.AuthorizeRequest(authCtx, req.GetUsername()); err != nil {
		log.Error("failed to authorize request", "err", err.Error())
		return nil, status.Error(codes.PermissionDenied, "access denied")
	}

	// validate request fields
	if err := ValidateCmd(req); err != nil {
		log.Error("invalid update profile request", "err", err.Error())
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	// get the profile record
	record, err := ps.profileStore.GetProfile(ctx, strings.TrimSpace(req.GetUsername()))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			log.Error(fmt.Sprintf("profile for %s not found", req.GetUsername()))
			return nil, status.Error(codes.NotFound, fmt.Sprintf("profile for %s not found", req.GetUsername()))
		} else {
			log.Error(fmt.Sprintf("failed to get profile record for %s", req.GetUsername()), "err", err.Error())
			return nil, status.Error(codes.Internal, "failed to get profile record")
		}
	}

	// prepare fields
	nickname := strings.TrimSpace(req.GetNickName())
	darkMode := req.GetDarkMode()

	// check if update is necessary
	if record.NickName.String == nickname && record.DarkMode == darkMode {

		log.Warn("no update necessary for profile record since no changes detected")
		return &api.Profile{
			Username: record.Username,
			NickName: proto.String(record.NickName.String),
			DarkMode: record.DarkMode,
		}, nil
	}

	// build updated record
	// only the below fields are updatable
	updated := &sqlc.Profile{
		Uuid: record.Uuid,
		NickName: sql.NullString{
			String: nickname,
			Valid:  len(nickname) > 0,
		},
		DarkMode:  darkMode,
		UpdatedAt: time.Now().UTC(),
	}

	// update the persistence layer
	if err := ps.profileStore.UpdateProfile(ctx, updated); err != nil {
		log.Error(fmt.Sprintf("failed to update profile record for %s", req.GetUsername()), "err", err.Error())
		return nil, status.Error(codes.Internal, "failed to update profile record")
	}

	// build the audit log fields
	var updatedFields []any

	if record.NickName.String != nickname {
		updatedFields = append(updatedFields, "nickname", nickname,
			slog.String("nickname_previous", record.NickName.String),
			slog.String("nickname_updated", nickname),
		)
	}

	if record.DarkMode != darkMode {
		updatedFields = append(updatedFields, "dark_mode", darkMode,
			slog.Bool("dark_mode_previous", record.DarkMode),
			slog.Bool("dark_mode_updated", darkMode),
		)
	}

	log.Info(fmt.Sprintf("successfully updated profile record for %s", req.GetUsername()), updatedFields...)

	// return the updated record
	return &api.Profile{
		Username: record.Username,
		NickName: proto.String(nickname),
		DarkMode: darkMode,
	}, nil
}
