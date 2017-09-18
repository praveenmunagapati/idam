package client

import (
	"context"
	"errors"
	"fmt"

	"github.com/homebot/core/urn"
	idamV1 "github.com/homebot/protobuf/pkg/api/idam/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// ConversionHandler is called for authentication questions
type ConversionHandler func(typ idamV1.ConversationChallengeType) (string, error)

// Authenticate authenticates at the IDAM server
func Authenticate(ctx context.Context, jwt string, conn *grpc.ClientConn, u urn.URN, conv ConversionHandler) (string, error) {
	cli := idamV1.NewAuthenticatorClient(conn)

	var md metadata.MD

	if jwt != "" {
		md = metadata.New(map[string]string{"authorization": jwt})
		fmt.Printf("%#v\n", md)
	}

	ctx = metadata.NewOutgoingContext(ctx, md)

	stream, err := cli.StartConversation(ctx)
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
			case idamV1.ConversationChallengeType_PASSWORD:
				secret, err := conv(question.GetType())
				if err != nil {
					return "", err
				}

				if err := stream.Send(buildPassword(secret)); err != nil {
					return "", err
				}
			case idamV1.ConversationChallengeType_TOTP:
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
		} else if success := msg.GetLoginSuccess(); success != nil {
			return success.GetToken(), err
		}
	}
}

func buildUsername(u urn.URN) *idamV1.ConversationResponse {
	return &idamV1.ConversationResponse{
		Type: idamV1.ConversationChallengeType_USERNAME,
		Response: &idamV1.ConversationResponse_Username{
			Username: u.String(),
		},
	}
}

func buildPassword(s string) *idamV1.ConversationResponse {
	return &idamV1.ConversationResponse{
		Type: idamV1.ConversationChallengeType_PASSWORD,
		Response: &idamV1.ConversationResponse_Password{
			Password: s,
		},
	}
}

func buildOTP(s string) *idamV1.ConversationResponse {
	return &idamV1.ConversationResponse{
		Type: idamV1.ConversationChallengeType_TOTP,
		Response: &idamV1.ConversationResponse_OneTimeSecret{
			OneTimeSecret: s,
		},
	}
}
