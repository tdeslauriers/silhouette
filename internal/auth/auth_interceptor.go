package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode"

	"github.com/tdeslauriers/carapace/pkg/jwt"
	api "github.com/tdeslauriers/silhouette/api/v1"
	"github.com/tdeslauriers/silhouette/internal/definitions"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

// AuthInterceptor is a gRPC server interceptor for handling authentication and authorization.
type AuthInterceptor interface {
	Unary() grpc.UnaryServerInterceptor
}

// NewAuthInterceptor creates a new instance of AuthInterceptor.
func NewAuthInterceptor(s2s, iam jwt.Verifier) AuthInterceptor {
	return &authInterceptor{
		s2s: s2s,
		iam: iam,

		logger: slog.Default().
			With(slog.String(definitions.PackageKey, definitions.PackageAuth)).
			With(slog.String(definitions.ComponentKey, definitions.ComponentAuthInterceptor)),
	}
}

// AuthInterceptor is the concrete implementation of the AuthInterceptor interface,
// a gRPC server interceptor for handling authentication and authorization.
type authInterceptor struct {
	s2s jwt.Verifier
	iam jwt.Verifier

	logger *slog.Logger
}

// Unary intercepts unary RPCs for authentication and authorization.
func (a *authInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {

		// get metadata from context, ie, headers
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			a.logger.Error("missing metadata in context")
			return nil, status.Error(codes.Unauthenticated, "missing metadata")
		}

		// extract the auth config from the called gRPC method
		authConfig, err := a.getAuthConfig(info.FullMethod)
		if err != nil {
			a.logger.Error("failed to get auth config", "err", err.Error())
			return nil, status.Error(codes.Internal, "failed to get auth config")
		}

		// get service authorization bearer token from from metadata/headers
		// dont need to check for self-access-allowed, so can use BuildAuthorized from carapace
		svcToken := md.Get("service-authorization")
		authedSvc, err := a.s2s.BuildAuthorized(authConfig.RequiredScopes, svcToken[0])
		if err != nil {
			a.logger.Error("failed to authorize service token", "err", err.Error())
			return nil, status.Error(codes.Unauthenticated, "unauthorized")
		}

		// get the access token from the metadata/headers
		accessToken := md.Get("authorization")

		// handle missing access token when service-only access is not allowed
		if !authConfig.S2SOnlyAllowed && len(accessToken) == 0 {
			a.logger.Error("no access token provided and service-only access is not allowed")
			return nil, status.Error(codes.Unauthenticated, "unauthorized")
		}

		// if the service token is missing, validate the service only access is allowed and
		// return an error if it is not
		if len(accessToken) == 0 {
			if !authConfig.S2SOnlyAllowed {
				a.logger.Error("no access token provided and service-only access is not allowed")
				return nil, status.Error(codes.Unauthenticated, "unauthorized")
			}

			// add the required scopes, authorized user, and service to the context for
			// downstream handlers to access and and determin authorization
			ctx = withAuthContext(ctx, &AuthContext{
				RequiredScopes:    authConfig.RequiredScopes,
				UserClaims:        nil, // no user claims for service-only requests
				SvcClaims:         &authedSvc.Claims,
				SelfAccessAllowed: authConfig.SelfAccessAllowed,
			})

			return handler(ctx, req)
		}

		// parse the access token
		userJot, err := jwt.BuildFromToken(accessToken[0])
		if err != nil {
			a.logger.Error("failed to build JWT from access token", "err", err.Error())
			return nil, status.Error(codes.Unauthenticated, "unauthorized")
		}

		// verify signature
		if err := a.iam.VerifySignature(userJot.BaseString, userJot.Signature); err != nil {
			a.logger.Error("failed to verify access token signature", "err", err.Error())
			return nil, status.Error(codes.Unauthenticated, "unauthorized")
		}

		// check access token issued time.
		// padding time to avoid clock sync issues.
		if time.Now().Add(2*time.Second).Unix() < userJot.Claims.IssuedAt {
			a.logger.Error(
				fmt.Sprintf("access token issued_at is in the future: %s",
					time.Unix(userJot.Claims.IssuedAt, 0).Format(time.RFC3339)),
			)
			return nil, status.Error(codes.Unauthenticated, "unauthorized")
		}

		// check access token expiry
		if time.Now().Unix() > userJot.Claims.Expires {
			a.logger.Error(
				fmt.Sprintf("access token expired at: %s",
					time.Unix(userJot.Claims.Expires, 0).Format(time.RFC3339)),
			)
			return nil, status.Error(codes.Unauthenticated, "unauthorized")
		}

		// check audiences
		if !hasRequiredAudience(definitions.ServiceProfile, userJot.Claims.MapAudiences()) {
			a.logger.Error(
				fmt.Sprintf("failed to authorize %s", userJot.Claims.Subject),
				"err", "access token does not have required audience",
			)
			return nil, status.Error(codes.PermissionDenied, "forbidden")
		}

		// add the required scopes, authorized user, and service to the context for
		// downstream handlers to access and and determin authorization
		ctx = withAuthContext(ctx, &AuthContext{
			RequiredScopes:    authConfig.RequiredScopes,
			UserClaims:        &userJot.Claims,
			SvcClaims:         &authedSvc.Claims,
			SelfAccessAllowed: authConfig.SelfAccessAllowed,
		})

		return handler(ctx, req)
	}
}

// getAuthConfig is a helper function which returns the authentication configuration for the calling gRPC method.
func (a *authInterceptor) getAuthConfig(fullMethod string) (*api.AuthConfig, error) {

	svcName, methodName := a.parseFullMethod(fullMethod)

	// get service description from service name
	desc, err := protoregistry.
		GlobalFiles.
		FindDescriptorByName(protoreflect.FullName(svcName))
	if err != nil {
		return nil, fmt.Errorf("failed to find descriptor for service %s: %w", svcName, err)
	}

	svcDesc, ok := desc.(protoreflect.ServiceDescriptor)
	if !ok {
		return nil, fmt.Errorf("descriptor for service %s is not a ServiceDescriptor", svcName)
	}

	methodDesc := svcDesc.Methods().ByName(protoreflect.Name(methodName))
	if methodDesc == nil {
		return nil, fmt.Errorf("method %s not found in service %s", methodName, svcName)
	}

	// get the authentication configuration from the method options
	opts := methodDesc.Options().(*api.AuthConfig)
	if opts == nil {
		return nil, fmt.Errorf("no authentication configuration found for method %s in service %s", methodName, svcName)
	}

	// get the extension/additional method options -> extenion field
	if proto.HasExtension(opts, api.E_AuthConfig) {
		ext := proto.GetExtension(opts, api.E_AuthConfig)
		if authConfig, ok := ext.(*api.AuthConfig); ok {
			return authConfig, nil
		}
		return nil, fmt.Errorf("failed to cast extension to AuthConfig for method %s in service %s", methodName, svcName)
	}

	return nil, fmt.Errorf("no authentication configuration extension found for method %s in service %s", methodName, svcName)
}

// parseFullMethod is a helper function which parses the full gRPC method string into service and method components.
func (a *authInterceptor) parseFullMethod(fullMethod string) (service, method string) {

	// check for empty:
	if len(fullMethod) == 0 || fullMethod[0] != '/' {
		return "", ""
	}

	// fullMethod is in the format of "/package.service/method"
	parts := strings.Split(fullMethod, "/")
	if len(parts) != 3 {
		return "", ""
	}

	service = parts[1]
	method = parts[2]

	return service, method
}

// hasRequiredAudience checks if the user has the required audience to access the resource
func hasRequiredAudience(requiredAudience string, userAudience map[string]bool) bool {

	return userAudience[requiredAudience]
}

// HasRequiredScopes checks if the user any one of the required scopes to access the resource
func hasRequiredScopes(requiredScopes []string, userScopes map[string]bool) bool {

	// check if the user has any one of the required scopes
	// return true on first match
	for _, scope := range requiredScopes {
		if userScopes[scope] {
			return true
		}
	}

	return false
}

// AuthContext holds authentication and authorization information for a request
type AuthContext struct {
	RequiredScopes    []string    // required scopes for the called method
	SvcClaims         *jwt.Claims // jwt claims for service tokens
	UserClaims        *jwt.Claims // jwt claims for user tokens
	SelfAccessAllowed bool        // indicates if the user is allowed to access their own resources
	S2sOnlyAllowed    bool        // indicates if service-only access is allowed (no user context required)
}

// contextKey is a private type to prevent collisions with other packages
type contextKey string

const authContextKey contextKey = "auth-context"

// withAuthContext adds the AuthContext to the context
func withAuthContext(ctx context.Context, authCtx *AuthContext) context.Context {

	return context.WithValue(ctx, authContextKey, authCtx)
}

// getAuthContext retrieves the AuthContext from the context
func GetAuthContext(ctx context.Context) (*AuthContext, error) {

	authCtx, ok := ctx.Value(authContextKey).(*AuthContext)
	if !ok {
		return nil, fmt.Errorf("auth-context does not exist in context")
	}

	return authCtx, nil
}

// AuthorizeRequest checks if a user has the correct scopes to access a resource and/or
// if self-access is allowed when accessing own resources.
// This impl will also check if the request params include a "username" field and if so,
// will check if the username in the request matches the authorized user's username in the
// token claims when self-access is allowed and no other scopes are present.
func AuthorizeRequest(auth *AuthContext, requestedUsername string) error {

	userScopes := auth.UserClaims.MapScopes()

	// check if user has any of the required scopes
	if hasRequiredScopes(auth.RequiredScopes, userScopes) {
		return nil
	}

	// if user does not have required scopes, check if self access is allowed and
	// deny access if it is not allowed
	if !auth.SelfAccessAllowed {
		return errors.New("user does not have required scopes and self access is not allowed")
	}

	// quick sanity check on the requested username to prevent
	// potential DoS or auth bypass with malicious usernames.
	requestedUsername = strings.TrimSpace(requestedUsername)
	if !isSafeForComparison(requestedUsername) {
		return errors.New("requested username is not valid/safe for comparison")
	}

	// if self access is allowed, check if the requested username matches
	// the authorized user's username in the token claims
	if auth.UserClaims.Subject != requestedUsername {
		return errors.New("for self access, requested username does not match authorized user")
	}

	return nil
}

// isSafeForComparison checks if a string is safe for comparison in authorization checks, such as
// usernames or other lookup/upsert parameter fields.
func isSafeForComparison(s string) bool {

	// not empty
	if s == "" {
		return false
	}

	// not absurdly long (DoS protection)
	if len(s) > 1000 {
		return false
	}

	// no dangerous characters
	if containsControlChars(s) {
		return false
	}

	return true
}

// containsControlChars checks if a string contains any control characters, which
// are not allowed lookup/upsert parameter fields.
func containsControlChars(s string) bool {
	for _, r := range s {
		if r == 0 || (unicode.IsControl(r) && r != '\t' && r != '\n' && r != '\r') {
			return true
		}
	}
	return false
}
