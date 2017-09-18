package policy

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"reflect"
	"strings"

	proto "github.com/golang/protobuf/proto"
	protobuf "github.com/golang/protobuf/protoc-gen-go/descriptor"
	"github.com/homebot/core/urn"
	"github.com/homebot/idam"
	"github.com/homebot/idam/token"
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

// JWTKeyVerifier provides the JWT verification key based on the issuer and
// algorithm specified in the token
type JWTKeyVerifier interface {
	// VerificationKey should return the verification key for the given issuer
	// and algorithm. It implements token.KeyProviderFunc
	VerificationKey(issuer string, alg string) (interface{}, error)
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

// Enforcer inspects unary and streaming RPC calls and enforces HomeBot access policies
// attached to the service definition
type Enforcer struct {
	services map[string]*protobuf.ServiceDescriptorProto
}

// NewEnforcer returns a new policy enforcer using the given protocol buffer files
// and `keyFn` for verifying JSON Web Tokens
func NewEnforcer(files []string) (*Enforcer, error) {
	p := &Enforcer{
		services: make(map[string]*protobuf.ServiceDescriptorProto),
	}

	for _, f := range files {
		descriptor := proto.FileDescriptor(f)
		if len(descriptor) == 0 {
			return nil, fmt.Errorf("unknown file: %s", f)
		}

		fd, err := extractFile(descriptor)
		if err != nil {
			return nil, err
		}

		pkgName := fd.GetPackage()

		for _, svc := range fd.Service {
			svcName := fmt.Sprintf("%s.%s", pkgName, svc.GetName())
			p.services[svcName] = svc
		}
	}

	if err := p.checkForErrors(); err != nil {
		return nil, err
	}

	return p, nil
}

func (p *Enforcer) getPolicy(methodName string) ([]*idamPolicy.PolicyRule, error) {
	parts := strings.Split(methodName, "/")
	svc := parts[1]
	method := parts[2]

	var policies []*idamPolicy.PolicyRule

L:
	for name, s := range p.services {
		if name != svc {
			continue
		}

		if s.GetOptions() != nil {
			p, err := proto.GetExtension(s.Options, homebot.E_MethodPolicy)
			if err == nil {
				servicePolicies, ok := p.([]*idamPolicy.PolicyRule)
				if !ok {
					return nil, errors.New("invalid policy message type")
				}

				policies = append(policies, servicePolicies...)
			}
		}

		for _, m := range s.Method {
			if m.GetName() == method && m.GetOptions() != nil {
				p, err := proto.GetExtension(m.Options, homebot.E_Policy)
				if err == nil {
					policy, ok := p.([]*idamPolicy.PolicyRule)
					if !ok {
						return nil, errors.New("invalid policy message type")
					}

					policies = append(policies, policy...)
				}
				break L
			}
		}
	}

	return policies, nil
}

// UnaryInterceptor inspects unary RPC calls and enforces HomeBot API policies attached
// to the service definition
func (p *Enforcer) UnaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	ctx, err := p.enforce(ctx, req, info.Server, false, info.FullMethod)
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
func (p *Enforcer) StreamInterceptor(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	ctx, err := p.enforce(stream.Context(), srv, nil, info.IsClientStream, info.FullMethod)
	if err != nil {
		return err
	}

	wrappedStream := &streamContextWrapper{
		ServerStream: stream,
		ctx:          ctx,
	}

	return handler(wrappedStream, stream)
}

func (p *Enforcer) enforce(ctx context.Context, srv interface{}, req interface{}, clientStreaming bool, methodName string) (context.Context, error) {
	policy, err := p.getPolicy(methodName)
	if err != nil {
		return ctx, err
	}

	verifier, ok := srv.(JWTKeyVerifier)
	if !ok {
		return nil, errors.New("server configuration error: cannot verify key")
	}

	jwt, tokenErr := token.FromMetadata(ctx, verifier.VerificationKey)

	authRequired := false

	for _, p := range policy {
		if !p.AllowAll && (p.AllowAuthenticated || p.OwnerOnly != "" || len(p.Roles) > 0) {
			authRequired = true
		}

		if authRequired && (tokenErr != nil || jwt == nil) {
			return ctx, idam.ErrNotAuthenticated
		}

		if !clientStreaming && p.OwnerOnly != "" && req != nil {
			typ := reflect.ValueOf(req).Elem().Type()
			props := proto.GetProperties(typ)
		L:
			for _, prop := range props.Prop {
				if p.OwnerOnly == prop.OrigName {
					val := reflect.ValueOf(req).Elem().FieldByName(prop.Name)

					if !jwt.OwnsURN(urn.URN(val.String())) {
						return ctx, idam.ErrNotAuthorized
					}

					break L
				}
			}
		}

		for _, r := range p.GetRoles() {
			if !jwt.HasGroup(urn.URN(r)) {
				return ctx, idam.ErrNotAuthorized
			}
		}
	}

	ctx = ContextWithToken(ctx, jwt)

	return ctx, nil
}

func (p *Enforcer) checkForErrors() error {
	for name, service := range p.services {
		if service.Options != nil {
			opt, err := proto.GetExtension(service.Options, homebot.E_MethodPolicy)
			if err == nil {
				sopt, ok := opt.([]*idamPolicy.PolicyRule)
				if !ok {
					return fmt.Errorf("invalid service option type for service %s", name)
				}

				for _, policy := range sopt {
					if policy.OwnerOnly != "" {
						return fmt.Errorf("%s: service option cannot use OwnerOnly", name)
					}
				}
			}
		}

		for _, method := range service.Method {
			methodName := method.GetName()

			if method.Options == nil {
				continue
			}

			opt, err := proto.GetExtension(method.Options, homebot.E_Policy)
			if err == nil {
				mopt, ok := opt.([]*idamPolicy.PolicyRule)
				if !ok {
					return fmt.Errorf("invalid method option on %s/%s", name, methodName)
				}

				for _, policy := range mopt {
					if (method.GetClientStreaming() || method.GetServerStreaming()) && policy.OwnerOnly != "" {
						return fmt.Errorf("streaming RPC cannot use OwnerOnly: %s.%s", name, methodName)
					}
				}
			}
		}
	}

	return nil
}
