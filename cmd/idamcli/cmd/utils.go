package cmd

import (
	"github.com/homebot/idam/client"
	"github.com/homebot/idam/token"
	"google.golang.org/grpc"
)

func conversation() (username, password, otp string, err error) {
	return "", "", "", nil
}

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
	}

	creds, err := client.NewIdamCredentials(idamServer, t, conversation, opts...)
	if err != nil {
		return nil, "", "", err
	}

	opts = append(opts, grpc.WithPerRPCCredentials(creds))

	conn, err := grpc.Dial(idamServer, opts...)
	if err != nil {
		return nil, "", "", err
	}

	return conn, tokenString, tokenFile, nil
}
