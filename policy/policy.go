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

type PolicyEnforcer struct {
	services map[string]*protobuf.ServiceDescriptorProto
	keyFn    token.KeyProviderFunc
}

func NewPolicyEnforcer(files []string, keyFn token.KeyProviderFunc) (*PolicyEnforcer, error) {
	p := &PolicyEnforcer{
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

	return p, nil
}

func (p *PolicyEnforcer) getPolicy(info *grpc.UnaryServerInfo) ([]*idamPolicy.PolicyRule, error) {
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

func (p *PolicyEnforcer) EnforcePolicy(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
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
