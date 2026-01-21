package auth

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

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
			With(definitions.PackageKey, definitions.PackageAuth).
			With(definitions.ComponentKey, definitions.ComponentAuthInterceptor),
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
		svcToken := md.Get("service-authorization")
		// TODO: update carapace jwt verifier code and insert here

		// get the access token from the metadata/headers
		accessToken := md.Get("authorization")
		// TODO: update carapace jwt verifier code and insert here

		// TODO: add the authorized user to the context

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

// AuthContext holds authentication and authorization information for a request
type AuthContext struct {
	SvcClaims  *jwt.Claims // jwt claims for service tokens
	UserClaims *jwt.Claims // jwt claims for user tokens
}

// contextKey is a private type to prevent collisions with other packages
type contextKey string

const authContextKey contextKey = "auth-context"

// withAuthContext adds the AuthContext to the context
func withAuthContext(ctx context.Context, authCtx *AuthContext) context.Context {
	return context.WithValue(ctx, authContextKey, authCtx)
}

// getAuthContext retrieves the AuthContext from the context
func GetAuthContext(ctx context.Context) *AuthContext {
	authCtx, ok := ctx.Value(authContextKey).(*AuthContext)
	if !ok {
		return nil
	}
	return authCtx
}
