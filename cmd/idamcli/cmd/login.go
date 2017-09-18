// Copyright © 2017 NAME HERE <EMAIL ADDRESS>
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"

	"github.com/howeyc/gopass"

	"github.com/homebot/core/urn"
	"github.com/homebot/idam/client"
	"github.com/homebot/idam/token"
	idamV1 "github.com/homebot/protobuf/pkg/api/idam/v1"
	"github.com/spf13/cobra"
)

// loginCmd represents the login command
var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Login to IDAM and retrieve a new authentication token",
	Run: func(cmd *cobra.Command, args []string) {
		conn, jwt, tokenFile, err := getClient()
		if err != nil {
			log.Fatal(err)
		}
		defer conn.Close()
		_ = tokenFile

		var userName urn.URN

		if jwt != "" {
			t, err := token.FromJWT(jwt, nil)
			if err != nil {
				log.Fatal(err)
			}
			userName = t.URN

		} else {
			fmt.Printf("Username: ")
			reader := bufio.NewReader(os.Stdin)
			line, _, err := reader.ReadLine()
			if err != nil {
				log.Fatal(err)
			}
			user := string(line)

			userName = urn.IdamIdentityResource.BuildURN("", user, user)
			if !userName.Valid() {
				log.Fatal(urn.ErrInvalidURN)
			}
		}

		newToken, err := client.Authenticate(context.Background(), "", conn, userName, func(typ idamV1.ConversationChallengeType) (string, error) {
			switch typ {
			case idamV1.ConversationChallengeType_PASSWORD:
				fmt.Printf("Password: ")
			case idamV1.ConversationChallengeType_TOTP:
				fmt.Printf("2FA-Token: ")
			}

			pass, err := gopass.GetPasswd()
			return string(pass), err
		})

		if err != nil {
			log.Fatal(err)
		}

		if err := token.SaveToken(newToken, tokenFile); err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	RootCmd.AddCommand(loginCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// loginCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// loginCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
