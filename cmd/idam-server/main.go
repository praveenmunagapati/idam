package main

import (
	"log"
	"net"

	"github.com/homebot/idam/policy"
	"github.com/homebot/idam/provider/file"
	"github.com/homebot/idam/server"
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

	policyEnforcer := policy.NewEnforcer([]string{
		"api/idam/v1/admin.proto",
		"api/idam/v1/profile.proto",
		"api/idam/v1/auth.proto",
	})

	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(policyEnforcer.UnaryInterceptor),
		grpc.StreamInterceptor(policyEnforcer.StreamInterceptor),
	)

	idam_api.RegisterIdentityManagerServer(grpcServer, srv)
	idam_api.RegisterAuthenticatorServer(grpcServer, srv)

	if err := grpcServer.Serve(listener); err != nil {
		log.Fatal(err)
	}
}
