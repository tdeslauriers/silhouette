package phone

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

// DeletePhone deletes a phone record by its slug.
func (ps *phoneServer) DeletePhone(ctx context.Context, req *api.DeletePhoneRequest) (*emptypb.Empty, error) {

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

	// authorize the request
	if err := auth.AuthorizeRequest(authCtx, req.GetUsername()); err != nil {
		log.Error("failed to authorize request", "err", err.Error())
		return nil, status.Error(codes.PermissionDenied, "access denied")
	}

	// validate fields in request
	if err := validate.ValidateUuid(strings.TrimSpace(req.GetPhoneSlug())); err != nil {
		log.Error("invalid phone slug", "err", "phone slug must be a valid UUID")
		return nil, status.Error(codes.InvalidArgument, "phone slug must be a valid UUID")
	}

	// get the phone records by the username
	// need to validate the slug exists and is associated with the given username
	phone, err := ps.phoneStore.GetPhone(
		ctx,
		strings.TrimSpace(req.GetPhoneSlug()),
		strings.TrimSpace(req.GetUsername()),
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			log.Error(
				fmt.Sprintf("phone slug %s record not found for user %s", req.GetPhoneSlug(), req.GetUsername()),
				"err", err.Error(),
			)
			return nil, status.Error(codes.NotFound, fmt.Sprintf("phone record not found for slug: %s", req.PhoneSlug))
		} else {
			log.Error(fmt.Sprintf("failed to get phone record for slug %s", req.GetPhoneSlug()), "err", err.Error())
			return nil, status.Error(codes.Internal, fmt.Sprintf("failed to get phone record for slug: %s", req.PhoneSlug))
		}
	}

	// delete the xref record
	if err := ps.xrefStore.RemovePhoneXrefByPhone(ctx, phone.Uuid); err != nil {
		log.Error("failed to delete phone xref record", "err", err.Error())
		return nil, status.Error(codes.Internal, "failed to delete phone xref record")
	}

	log.Info(
		fmt.Sprintf("successfully deleted phone xref record for phone slug %s and user %s",
			req.GetPhoneSlug(),
			req.GetUsername()),
	)

	// delete the phone record
	if err := ps.phoneStore.DeletePhone(ctx, phone.Uuid); err != nil {
		log.Error("failed to delete phone record", "err", err.Error())
		return nil, status.Error(codes.Internal, "failed to delete phone record")
	}

	log.Info(fmt.Sprintf("successfully deleted phone record for phone slug %s", req.GetPhoneSlug()))

	return &emptypb.Empty{}, nil
}
