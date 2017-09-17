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
	keyFn    token.KeyProviderFunc
}

// NewEnforcer returns a new policy enforcer using the given protocol buffer files
// and `keyFn` for verifying JSON Web Tokens
func NewEnforcer(files []string, keyFn token.KeyProviderFunc) (*Enforcer, error) {
	p := &Enforcer{
		services: make(map[string]*protobuf.ServiceDescriptorProto),
		keyFn:    keyFn,
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

func (p *Enforcer) getPolicy(info *grpc.UnaryServerInfo) ([]*idamPolicy.PolicyRule, error) {
	parts := strings.Split(info.FullMethod, "/")
	svc := parts[1]
	method := parts[2]

	for name, s := range p.services {
		if name != svc {
			continue
		}

		for _, m := range s.Method {
			if m.GetName() == method {
				p, err := proto.GetExtension(m.Options, homebot.E_Policy)
				if err != nil {
					return nil, err
				}

				policy, ok := p.([]*idamPolicy.PolicyRule)
				if !ok {
					return nil, errors.New("invalid policy message type")
				}

				return policy, nil
			}
		}
	}

	return nil, nil
}

// UnaryInspector inspects unary RPC calls and enforces HomeBot API policies attached
// to the service definition
func (p *Enforcer) UnaryInspector(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	return p.enforce(ctx, req, info, handler)

}

// StreamInspector inspects stream RPCs and enforces HomeBot APi policies attached to
// the service definition
func (p *Enforcer) StreamInspector(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	// TODO
	return handler(srv, stream)
}

func (p *Enforcer) enforce(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	policy, err := p.getPolicy(info)
	if err != nil {
		return nil, err
	}

	jwt, tokenErr := token.FromMetadata(ctx, p.keyFn)

	authRequired := false

	for _, p := range policy {
		if !p.AllowAll && (p.AllowAuthenticated || p.OwnerOnly != "" || len(p.Roles) > 0) {
			authRequired = true
		}

		if authRequired && (tokenErr != nil || jwt == nil) {
			return nil, idam.ErrNotAuthenticated
		}

		if p.OwnerOnly != "" {
			typ := reflect.ValueOf(req).Elem().Type()
			props := proto.GetProperties(typ)
		L:
			for _, prop := range props.Prop {
				if p.OwnerOnly == prop.OrigName {
					val := reflect.ValueOf(req).Elem().FieldByName(prop.Name)

					if !jwt.OwnsURN(urn.URN(val.String())) {
						return nil, idam.ErrNotAuthorized
					}

					break L
				}
			}
		}

		for _, r := range p.GetRoles() {
			if !jwt.HasGroup(urn.URN(r)) {
				return nil, idam.ErrNotAuthorized
			}
		}
	}

	return handler(ctx, req)
}

func (p *Enforcer) checkForErrors() error {
	for name, service := range p.services {
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

		for _, method := range service.Method {
			methodName := method.GetName()

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
