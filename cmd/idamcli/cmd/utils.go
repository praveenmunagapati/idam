package cmd

import (
	"bufio"
	"fmt"
	"log"
	"os"

	"github.com/howeyc/gopass"

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

	userName := fmt.Sprintf("user:%s", user)

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

	return userName, string(pass), string(otpb), nil
}

func newClient() (client.Client, error) {
	t, path, _ := token.LoadToken([]string{jwtFile})
	cli, err := client.NewAuthenticatedClient(idamServer, t, conversation, grpc.WithInsecure())
	if err != nil {
		return nil, err
	}

	cli.Creds().OnAuthenticated(func(t *token.Token) {
		if path == "" {
			path = token.DefaultTokenFile
		}

		if err := token.SaveToken(t.JWT, path); err != nil {
			log.Printf("failed to save token: %s\n", err)
		}
	})

	if cli.Creds().Token() != nil && cli.Creds().Token().JWT != t {
		if path == "" {
			path = token.DefaultTokenFile
		}

		if err := token.SaveToken(cli.Creds().Token().JWT, path); err != nil {
			log.Printf("failed to save token: %s\n", err)
		}
	}

	return cli, nil
}

func newAdminClient() (client.AdminClient, error) {
	t, path, _ := token.LoadToken([]string{jwtFile})
	cli, err := client.NewAuthenticatedAdminClient(idamServer, t, conversation, grpc.WithInsecure())
	if err != nil {
		return nil, err
	}

	cli.Creds().OnAuthenticated(func(t *token.Token) {
		if path == "" {
			path = token.DefaultTokenFile
		}

		if err := token.SaveToken(t.JWT, path); err != nil {
			log.Printf("failed to save token: %s\n", err)
		}
	})

	if cli.Creds().Token() != nil && cli.Creds().Token().JWT != t {
		if path == "" {
			path = token.DefaultTokenFile
		}

		if err := token.SaveToken(cli.Creds().Token().JWT, path); err != nil {
			log.Printf("failed to save token: %s\n", err)
		}
	}

	return cli, nil
}
