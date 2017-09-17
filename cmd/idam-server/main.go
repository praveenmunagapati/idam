package main

import (
	"log"
	"net"

	"github.com/homebot/idam"
	"github.com/homebot/idam/provider/file"
	"github.com/homebot/idam/server"
	"google.golang.org/grpc"
)

func main() {
	idam.TestPolicy()
	mng := file.New("./accounts.json")

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
