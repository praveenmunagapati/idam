package main

import (
	"log"
	"net"

	"github.com/homebot/idam/policy"
	"github.com/homebot/idam/provider/file"
	"github.com/homebot/idam/server"
	idamV1 "github.com/homebot/protobuf/pkg/api/idam/v1"
	"google.golang.org/grpc"
)

func main() {
	mng := file.New("./accounts.json")

	srv, err := server.New(mng, server.WithSharedKey("foobar"))
	if err != nil {
		log.Fatal(err)
	}

	listener, err := net.Listen("tcp", ":50053")
	if err != nil {
		log.Fatal(err)
	}

	policyEnforcer, err := policy.NewEnforcer([]string{
		"api/idam/v1/admin.proto",
		"api/idam/v1/profile.proto",
		"api/idam/v1/auth.proto",
	})

	if err != nil {
		log.Fatal(err)
	}

	grpcServer := grpc.NewServer(policyEnforcer.ServerOptions()...)

	idamV1.RegisterAdminServer(grpcServer, srv)
	idamV1.RegisterProfileServer(grpcServer, srv)
	idamV1.RegisterAuthenticatorServer(grpcServer, srv)

	if err := grpcServer.Serve(listener); err != nil {
		log.Fatal(err)
	}
}
