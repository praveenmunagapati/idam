package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/howeyc/gopass"

	"github.com/homebot/core/urn"
	"github.com/homebot/idam/client"
	"github.com/homebot/idam/token"
	"google.golang.org/grpc"
)

func conversation() (username, password, otp string, err error) {
	fmt.Printf("Username: ")
	reader := bufio.NewReader(os.Stdin)
	line, _, err := reader.ReadLine()
	if err != nil {
		log.Fatal(err)
	}
	user := string(line)

	userName := urn.IdamIdentityResource.BuildURN("", user, user)
	if !userName.Valid() {
		return "", "", "", errors.New("invalid username")
	}

	fmt.Printf("Password: ")
	pass, err := gopass.GetPasswd()
	if err != nil {
		return "", "", "", err
	}

	fmt.Printf("2FA-Token: ")
	otpb, err := gopass.GetPasswd()
	if err != nil {
		return "", "", "", err
	}

	return userName.String(), string(pass), string(otpb), nil
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

	creds.OnAuthenticated(func(t *token.Token) {
		if path == "" {
			path = token.DefaultTokenFile
		}

		if err := token.SaveToken(t.JWT, path); err != nil {
			log.Printf("failed to save token: %s\n", err)
		}
	})

	if creds.Token() != nil && creds.Token().JWT != t {
		if path == "" {
			path = token.DefaultTokenFile
		}

		if err := token.SaveToken(creds.Token().JWT, path); err != nil {
			log.Printf("failed to save token: %s\n", err)
		}

		tokenString = creds.Token().JWT
	}

	opts = append(opts, grpc.WithPerRPCCredentials(creds))

	conn, err := grpc.Dial(idamServer, opts...)
	if err != nil {
		return nil, "", "", err
	}

	return conn, tokenString, tokenFile, nil
}
