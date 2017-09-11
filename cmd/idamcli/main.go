package main

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/homebot/core/urn"
	"github.com/homebot/idam/client"
	idam_api "github.com/homebot/protobuf/pkg/api/idam"
	"github.com/howeyc/gopass"

	"google.golang.org/grpc"
)

func main() {
	conn, err := grpc.Dial("localhost:50053", grpc.WithInsecure())
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	u := urn.IdamIdentityResource.BuildURN("", "admin", "admin")

	token, err := client.Authenticate(context.Background(), conn, u, func(typ idam_api.QuestionType) (string, error) {
		question := ""

		switch typ {
		case idam_api.QuestionType_PASSWORD:
			question = "Password: "
		case idam_api.QuestionType_OTP:
			question = "One-Time-Password: "
		default:
			return "", errors.New("unexpected question type")
		}

		fmt.Printf(question)
		pass, err := gopass.GetPasswd()
		if err != nil {
			return "", err
		}

		return string(pass), nil
	})

	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Token: %s\n", token)
}
