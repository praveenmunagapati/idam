package main

import (
	"log"
	"net"

	"golang.org/x/crypto/bcrypt"

	"github.com/homebot/idam"
	"github.com/homebot/idam/policy"
	"github.com/homebot/idam/provider/file"
	"github.com/homebot/idam/server"
	"github.com/homebot/insight/logger"
	idamV1 "github.com/homebot/protobuf/pkg/api/idam/v1"
	"google.golang.org/grpc"
)

func main() {

	identities := file.NewIdentityProvider("./accounts.json")
	roles := file.NewRoleProvider("./roles.json")
	permissions := file.NewPermissionProvider("./permissions.json")

	list, err := identities.List()
	if err != nil {
		log.Fatal(err)
	}

	r, err := roles.List()
	if err != nil {
		log.Fatal(err)
	}

	pl, err := permissions.List()
	if err != nil {
		log.Fatal(err)
	}

	if len(pl) == 0 {
		for _, p := range idam.AllBuiltInPermissions {
			if _, err := permissions.New(p, "service:system"); err != nil {
				log.Fatal(err)
			} else {
				log.Printf("created system permission: %s\n", p)
			}
		}
	}

	if len(r) == 0 {
		if _, err := roles.New(&idam.Role{
			Name:        "idam-admin",
			Permissions: idam.AllBuiltInPermissions,
		}); err != nil {
			log.Fatal(err)
		} else {
			log.Printf("created system role: %s\n", "idam-admin")
		}
	}

	if len(list) == 0 {
		user := idam.NewUserIdentity("user:admin", "", []string{"idam-admin"}, nil)
		user.FirstName = "Admin"
		user.LastName = "Mustermann"
		user.MailAddresses = []string{"admin@example.com"}

		pass, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
		if err != nil {
			log.Fatal(err)
		}

		if _, err := identities.New(user, pass); err != nil {
			log.Fatal(err)
		} else {
			log.Printf("created system identity: user:admin\n")
		}
	}

	l, err := logger.NewInsightLogger(logger.WithServiceType("idam"))
	if err != nil {
		log.Fatal(err)
	}

	srv, err := server.New(identities, roles, permissions, server.WithSharedKey("foobar"), server.WithLogger(l))
	if err != nil {
		log.Fatal(err)
	}

	listener, err := net.Listen("tcp", ":50053")
	if err != nil {
		log.Fatal(err)
	}

	policyEnforcer, err := policy.NewEnforcer(
		"homebot/api/idam/v1/identity.proto",
		"homebot/api/idam/v1/permissions.proto",
		"homebot/api/idam/v1/profile.proto",
		"homebot/api/idam/v1/auth.proto",
	)

	policyEnforcer.SetLogger(l)

	if err != nil {
		log.Fatal(err)
	}

	grpcServer := grpc.NewServer(policyEnforcer.ServerOptions()...)

	idamV1.RegisterPermissionsServer(grpcServer, srv)
	idamV1.RegisterProfileServer(grpcServer, srv)
	idamV1.RegisterAuthenticatorServer(grpcServer, srv)
	idamV1.RegisterIdentityServiceServer(grpcServer, srv)

	if err := grpcServer.Serve(listener); err != nil {
		log.Fatal(err)
	}
}
