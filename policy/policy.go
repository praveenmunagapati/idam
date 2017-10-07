// Package policy provides a unary and stream interceptor for gRPC
// that enforces HomeBot access policies attached to the protobuf
// definitions of services and methods. Access is granted based on
// a set of required permissions that must be present in a JWT authorization
// bearer as the "granted" claim.
//
// Currently one needs to specify the relative imports paths of the proto
// files that contain the service definitions. This may be improved once
// https://github.com/grpc/grpc-go/issues/1526 is resolved.
//
// In order for the policy enforcer to work, the gRPC server interface
// must implement the `PolicyEnforcedServer` interface.
//
// Usage:
//
//   service MyService {
//		rpc MyMethod(Request) returns (Response) {
//			option (homebot.api.policy) = {
//				permissions: [
//					"myservice.myresource.read",
//					"myservice.myresource.write",
//				]
//			}
//		}
//   }
//
// Now add a policy enforcer to you gRPC server:
//
//		enforcer, err := policy.NewEnforcer("myservice.proto")
//
//		srv := grpc.NewServer("0.0.0.0:52000", enforcer.ServerOptions()...)
//
package policy

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"reflect"

	proto "github.com/golang/protobuf/proto"
	protobuf "github.com/golang/protobuf/protoc-gen-go/descriptor"
	"github.com/homebot/idam/token"
	"github.com/homebot/insight/logger"
	homebot "github.com/homebot/protobuf/pkg/api"
	idamPolicy "github.com/homebot/protobuf/pkg/api/idam/policy"
	"google.golang.org/grpc"
)

type policyTokenKey struct{}

// PolicyTokenKey is used to store authentication tokens in a context
var PolicyTokenKey = &policyTokenKey{}

// TokenFromContext returns the authentication token from the context
func TokenFromContext(ctx context.Context) (*token.Token, bool) {
	t, ok := ctx.Value(PolicyTokenKey).(*token.Token)
	return t, ok
}

// ContextWithToken sets the authentication token on the context
func ContextWithToken(ctx context.Context, token *token.Token) context.Context {
	return context.WithValue(ctx, PolicyTokenKey, token)
}

// OwnerException is an additional policy that is applied if the
// identity that performs the request owns the resource it want's
// to operate on
type OwnerException struct {
	// AlwaysAllow is set to true if the request should always
	// be allowed it the identity is the resource owner
	AlwaysAllow bool

	// GrantPermissions is a list of permissions that are implicitly
	// granted to the resource owner
	GrantPermissions []string

	// ResourceNameField holds the name of the field that contains the
	// resource name
	ResourceNameField string
}

// Policy defines access policies for service methods
type Policy struct {
	// RequiredPermissions is a list of permissions an identity must
	// have in order to perform the request
	RequiredPermissions []string

	// AllowAuthenticated may be set to true to allow all authenticated
	// identities
	AllowAuthenticated bool

	// OwnerException is an additional policy that is applied if the
	// identity that performs the request owns the resource it want's
	// to operate on
	OwnerException *OwnerException
}

type PolicyEnforcedServer interface {
	IsResourceOwner(resource, identity string, permissions []string) (bool, error)

	VerificationKey(issuer string, alg string) (interface{}, error)
}

// Enforcer enforces homebot API policies
type Enforcer struct {
	methods map[string][]Policy
	logger  logger.Logger
}

// NewEnforcer creates a new policy enforcer
func NewEnforcer(files ...string) (*Enforcer, error) {
	e := &Enforcer{
		methods: make(map[string][]Policy),
		logger:  logger.NopLogger{},
	}

	if err := e.buildPolicies(files); err != nil {
		return nil, err
	}

	return e, nil
}

// SetLogger sets the logger for the enforcer
func (e *Enforcer) SetLogger(l logger.Logger) {
	if l == nil {
		e.logger = logger.NopLogger{}
		return
	}

	e.logger = l
}

// ServerOptions returns a slice of gRPC server options to enable the
// enforcer
func (e *Enforcer) ServerOptions() []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.StreamInterceptor(e.StreamInterceptor),
		grpc.UnaryInterceptor(e.UnaryInterceptor),
	}
}

// UnaryInterceptor inspects unary RPC calls and enforces HomeBot API policies attached
// to the service definition
func (e *Enforcer) UnaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	ctx, err := e.enforcePolicy(ctx, info.Server, req, false, info.FullMethod)
	if err != nil {
		return nil, err
	}

	return handler(ctx, req)
}

type streamContextWrapper struct {
	grpc.ServerStream

	ctx context.Context
}

func (s *streamContextWrapper) Context() context.Context {
	return s.ctx
}

// StreamInterceptor inspects stream RPCs and enforces HomeBot API policies attached to
// the service definition
func (e *Enforcer) StreamInterceptor(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	ctx, err := e.enforcePolicy(stream.Context(), srv, nil, info.IsClientStream, info.FullMethod)
	if err != nil {
		return err
	}

	wrappedStream := &streamContextWrapper{
		ServerStream: stream,
		ctx:          ctx,
	}

	return handler(srv, wrappedStream)
}

func (e *Enforcer) enforcePolicy(ctx context.Context, srv interface{}, req interface{}, clientStreaming bool, methodName string) (context.Context, error) {
	policies := e.methods[methodName]

	logger := e.logger.WithResource(methodName)

	if len(policies) == 0 {
		logger.Infof("no policies definied; granting access")
		return ctx, nil
	}

	s, ok := srv.(PolicyEnforcedServer)
	if !ok {
		return ctx, errors.New("not a policy enforced server")
	}

	jwt, tokenErr := token.FromMetadata(ctx, s.VerificationKey)
	if tokenErr != nil {
		return ctx, tokenErr
	}

	logger = logger.WithIdentity(jwt.Name)

	ctx = ContextWithToken(ctx, jwt)

	// Check if there's a policy allowing all authenticated users
	for _, p := range policies {
		if p.AllowAuthenticated {
			logger.Infof("granting access: allow-authenticated")
			return ctx, nil
		}
	}

	for _, p := range policies {
		// if we have an owner exception configured, apply it now
		permissions := jwt.Permissions

		if p.OwnerException != nil {
			var resource string

			if p.OwnerException.ResourceNameField == "{token}" {
				resource = jwt.Name
			} else {
				var ok bool

				resource, ok = getProtoField(req, p.OwnerException.ResourceNameField)
				if !ok {
					return ctx, errors.New("message does not contain name field")
				}
			}

			ok, err := s.IsResourceOwner(resource, jwt.Name, jwt.Permissions)
			if err != nil {
				return ctx, err
			}

			if ok {
				if p.OwnerException.AlwaysAllow {
					logger.Infof("granting access: allow-owner")

					return ctx, nil
				}
				if p.AllowAuthenticated {
					continue
				}

				permissions = append(permissions, p.RequiredPermissions...)
			}
		}

	L:
		for _, perm := range p.RequiredPermissions {
			for _, granted := range permissions {
				if perm == granted {
					continue L
				}
			}

			logger.Warnf("access denied: permission %q missing", perm)
			return ctx, errors.New("not authorized")
		}
	}

	logger.Infof("granting access: all policies ok")
	return ctx, nil
}

func getProtoField(req interface{}, field string) (string, bool) {
	typ := reflect.ValueOf(req).Elem().Type()
	props := proto.GetProperties(typ)

	for _, prop := range props.Prop {
		if field == prop.OrigName {
			val := reflect.ValueOf(req).Elem().FieldByName(prop.Name)

			return val.String(), true
		}
	}

	return "", false
}

func (e *Enforcer) buildPolicies(files []string) error {
	for _, f := range files {
		descriptor := proto.FileDescriptor(f)

		if len(descriptor) == 0 {
			return fmt.Errorf("unknown file: %s", f)
		}

		fd, err := extractFile(descriptor)
		if err != nil {
			return err
		}

		pkgName := fd.GetPackage()

		for _, svc := range fd.Service {
			svcPolicies, err := buildServicePolicies(svc)
			if err != nil {
				return err
			}

			svcName := fmt.Sprintf("%s.%s", pkgName, svc.GetName())

			for _, method := range svc.Method {
				methodName := fmt.Sprintf("/%s/%s", svcName, method.GetName())

				policies, err := buildMethodPolicies(method)
				if err != nil {
					return err
				}

				if len(policies) > 0 || len(svcPolicies) > 0 {
					e.methods[methodName] = append(svcPolicies, policies...)
				}
			}
		}
	}

	return nil
}

func buildServicePolicies(m *protobuf.ServiceDescriptorProto) ([]Policy, error) {
	options := m.GetOptions()

	if options != nil {
		extension, err := proto.GetExtension(options, homebot.E_MethodPolicy)
		if protoPolicies, ok := extension.([]*idamPolicy.PolicyRule); err == nil && ok {
			var policies []Policy

			for _, polpb := range protoPolicies {
				if polpb.AllowAll {
					return nil, nil
				}

				pol := Policy{
					RequiredPermissions: polpb.GetPermissions(),
					AllowAuthenticated:  polpb.GetAllowAuthenticated(),
				}

				if owner := polpb.GetIfOwner(); owner != nil {
					pol.OwnerException = &OwnerException{
						AlwaysAllow:       owner.GetAllow(),
						GrantPermissions:  owner.GetGrantPermissions(),
						ResourceNameField: owner.GetResource(),
					}
				}

				policies = append(policies, pol)
			}

			return policies, nil
		} else if err == nil && !ok {
			return nil, errors.New("invalid extension type")
		}
	}

	return nil, nil
}

func buildMethodPolicies(m *protobuf.MethodDescriptorProto) ([]Policy, error) {
	options := m.GetOptions()

	if options != nil {
		extension, err := proto.GetExtension(options, homebot.E_Policy)
		if protoPolicies, ok := extension.([]*idamPolicy.PolicyRule); err == nil && ok {
			var policies []Policy

			for _, polpb := range protoPolicies {
				if polpb.AllowAll {
					return nil, nil
				}

				pol := Policy{
					RequiredPermissions: polpb.GetPermissions(),
					AllowAuthenticated:  polpb.GetAllowAuthenticated(),
				}

				if owner := polpb.GetIfOwner(); owner != nil {
					pol.OwnerException = &OwnerException{
						AlwaysAllow:       owner.GetAllow(),
						GrantPermissions:  owner.GetGrantPermissions(),
						ResourceNameField: owner.GetResource(),
					}
				}

				policies = append(policies, pol)
			}

			return policies, nil
		} else if err == nil && !ok {
			return nil, errors.New("invalid extension type")
		}
	}

	return nil, nil
}

func extractFile(gz []byte) (*protobuf.FileDescriptorProto, error) {
	r, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, fmt.Errorf("failed to open gzip reader: %v", err)
	}
	defer r.Close()

	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to uncompress descriptor: %v", err)
	}

	fd := new(protobuf.FileDescriptorProto)
	if err := proto.Unmarshal(b, fd); err != nil {
		return nil, fmt.Errorf("malformed FileDescriptorProto: %v", err)
	}

	return fd, nil
}
