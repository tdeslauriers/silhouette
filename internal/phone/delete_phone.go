package phone

import (
	"context"
	"strings"

	"github.com/tdeslauriers/carapace/pkg/validate"
	api "github.com/tdeslauriers/silhouette/api/v1"
	"github.com/tdeslauriers/silhouette/internal/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// DeletePhone deletes a phone record by its slug.
func (ps *phoneServer) DeletePhone(ctx context.Context, req *api.DeletePhoneRequest) (*emptypb.Empty, error) {

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

		// redundant, auth interceptor should deny this, but good practice
		if !authCtx.SelfAccessAllowed {
			log.Error("access denied: user does not have required scopes and self access is not allowed")
			return nil, status.Error(codes.PermissionDenied, "access denied")
		}

		// self access allowed, so requested username must == authenticated user's username
		if authCtx.UserClaims.Subject != req.GetUsername() {
			log.Error("access denied", "err", "you may only delete a phone record for your own profile")
			return nil, status.Error(codes.PermissionDenied, "you may only delete a phone record for your own profile")
		}
	}

	// validate fields in request
	if !validate.IsValidUuid(strings.TrimSpace(req.GetPhoneSlug())) {
		log.Error("invalid phone slug", "err", "phone slug must be a valid UUID")
		return nil, status.Error(codes.InvalidArgument, "phone slug must be a valid UUID")
	}

	// get the phone records by the username

	// get the specific phone correct phone record by the slug
	// to make sure the user actually owns the phone record

	// delete the xref

	// delete the phone record

	return &emptypb.Empty{}, nil
}
