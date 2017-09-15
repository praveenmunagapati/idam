package cmd

import (
	"github.com/homebot/idam/token"
	"google.golang.org/grpc"
)

func getClient() (*grpc.ClientConn, string, string, error) {
	tokenString := ""
	tokenFile := ""

	opts := []grpc.DialOption{
		grpc.WithInsecure(),
	}

	t, path, err := token.LoadToken([]string{jwtFile})
	if err == nil {
		tokenString = t
		tokenFile = path
		opts = append(opts, grpc.WithPerRPCCredentials(token.NewRPCCredentials(t)))
	}

	conn, err := grpc.Dial(idamServer, opts...)
	if err != nil {
		return nil, "", "", err
	}

	return conn, tokenString, tokenFile, nil
}
