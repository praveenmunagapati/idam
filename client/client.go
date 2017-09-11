package client

import (
	"context"
	"errors"
	"fmt"

	"github.com/homebot/core/urn"
	idam_api "github.com/homebot/protobuf/pkg/api/idam"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// ConversionHandler is called for authentication questions
type ConversionHandler func(typ idam_api.QuestionType) (string, error)

// Authenticate authenticates at the IDAM server
func Authenticate(ctx context.Context, jwt string, conn *grpc.ClientConn, u urn.URN, conv ConversionHandler) (string, error) {
	cli := idam_api.NewAuthenticatorClient(conn)

	var md metadata.MD

	if jwt != "" {
		md = metadata.New(map[string]string{"authorization": jwt})
		fmt.Printf("%#v\n", md)
	}

	ctx = metadata.NewOutgoingContext(ctx, md)

	stream, err := cli.Authenticate(ctx)
	if err != nil {
		return "", err
	}
	defer stream.CloseSend()

	// send username
	if err := stream.Send(buildUsername(u)); err != nil {
		return "", err
	}

	for {
		msg, err := stream.Recv()
		if err != nil {
			return "", err
		}

		if question := msg.GetQuestion(); question != nil {
			switch question.GetType() {
			case idam_api.QuestionType_PASSWORD:
				secret, err := conv(question.GetType())
				if err != nil {
					return "", err
				}

				if err := stream.Send(buildPassword(secret)); err != nil {
					return "", err
				}
			case idam_api.QuestionType_OTP:
				secret, err := conv(question.GetType())
				if err != nil {
					return "", err
				}

				if err := stream.Send(buildOTP(secret)); err != nil {
					return "", err
				}
			default:
				return "", errors.New("unexpected question")
			}
		} else if token := msg.GetToken(); token != "" {
			return token, err
		}
	}
}

func buildUsername(u urn.URN) *idam_api.Answer {
	return &idam_api.Answer{
		Type: idam_api.QuestionType_USERNAME,
		Payload: &idam_api.Answer_Username{
			Username: &idam_api.UserName{
				Urn: urn.ToProtobuf(u),
			},
		},
	}
}

func buildPassword(s string) *idam_api.Answer {
	return &idam_api.Answer{
		Type: idam_api.QuestionType_PASSWORD,
		Payload: &idam_api.Answer_Secret{
			Secret: s,
		},
	}
}

func buildOTP(s string) *idam_api.Answer {
	return &idam_api.Answer{
		Type: idam_api.QuestionType_OTP,
		Payload: &idam_api.Answer_Secret{
			Secret: s,
		},
	}
}
