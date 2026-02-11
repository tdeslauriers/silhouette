package address

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	exo "github.com/tdeslauriers/carapace/pkg/connect/grpc"
	"github.com/tdeslauriers/carapace/pkg/validate"
	api "github.com/tdeslauriers/silhouette/api/v1"
	"github.com/tdeslauriers/silhouette/internal/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// DeleteAddress deletes an address record from the database, returning an empty response if successful
func (s *addressServer) DeleteAddress(ctx context.Context, req *api.DeleteAddressRequest) (*emptypb.Empty, error) {

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

	// validate the slug
	if !validate.IsValidUuid(strings.TrimSpace(req.GetSlug())) {
		log.Error("invalid address slug", "err", "address slug must be a valid UUID")
		return nil, status.Error(codes.InvalidArgument, "address slug must be a valid UUID")
	}

	// get the address record by slug and username to ensure it exists and belongs to the user
	address, err := s.addressStore.GetAddress(
		ctx,
		strings.TrimSpace(req.GetSlug()),
		strings.TrimSpace(req.GetUsername()),
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			log.Error(
				fmt.Sprintf("address slug %s record not found for user %s", req.GetSlug(), req.GetUsername()),
				"err", err.Error(),
			)
			return nil, status.Error(codes.NotFound, fmt.Sprintf("address record not found for slug: %s", req.GetSlug()))
		} else {
			log.Error(fmt.Sprintf("failed to get address record for slug %s", req.GetSlug()), "err", err.Error())
			return nil, status.Error(codes.Internal, fmt.Sprintf("failed to get address record for slug: %s", req.GetSlug()))
		}
	}

	// delete the xref record
	if err := s.xrefStore.RemoveAddressXrefByAddress(ctx, address.Uuid); err != nil {
		log.Error("failed to delete address xref record", "err", err.Error())
		return nil, status.Error(codes.Internal, "failed to delete address xref record")
	}

	log.Info(
		fmt.Sprintf("successfully deleted address xref record for address slug %s and user %s",
			req.GetSlug(),
			req.GetUsername()),
	)

	// delete the address record
	if err := s.addressStore.DeleteAddress(ctx, address.Uuid); err != nil {
		log.Error("failed to delete address record", "err", err.Error())
		return nil, status.Error(codes.Internal, "failed to delete address record")
	}

	log.Info(fmt.Sprintf("successfully deleted address record for address slug %s", req.GetSlug()))

	return &emptypb.Empty{}, nil
}
