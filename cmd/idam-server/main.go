package main

import (
	"fmt"
	"log"
	"net"

	"github.com/homebot/idam"
	"github.com/homebot/idam/provider/memory"
	"github.com/homebot/idam/server"
	idam_api "github.com/homebot/protobuf/pkg/api/idam"
	"google.golang.org/grpc"
)

func main() {
	mng := memory.New()

	otpSecret, err := mng.Create(idam.Identity{
		Name: "admin",
	}, "mypass", true)

	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("OTP-Secret: %s\n", otpSecret)

	srv, err := server.New(mng, server.WithSharedKey("foobar"))
	if err != nil {
		log.Fatal(err)
	}

	listener, err := net.Listen("tcp", ":50053")
	if err != nil {
		log.Fatal(err)
	}

	grpcServer := grpc.NewServer()
	idam_api.RegisterIdentityManagerServer(grpcServer, srv)
	idam_api.RegisterAuthenticatorServer(grpcServer, srv)

	if err := grpcServer.Serve(listener); err != nil {
		log.Fatal(err)
	}
}
