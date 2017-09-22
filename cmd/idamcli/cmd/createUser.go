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
	"context"
	"fmt"
	"log"

	"github.com/howeyc/gopass"

	"github.com/homebot/core/urn"
	"github.com/homebot/idam"
	idamV1 "github.com/homebot/protobuf/pkg/api/idam/v1"

	"github.com/spf13/cobra"
)

var (
	cuPassword      string
	cuOTP           bool
	cuFirstName     string
	cuLastName      string
	cuMail          string
	cuSeconaryMails []string
	cuRoles         []string
)

// createUserCmd represents the user command
var createUserCmd = &cobra.Command{
	Use:   "user",
	Short: "Create a new user account",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 1 {
			log.Fatal("invalid number of parameters")
		}

		username := args[0]

		if u := urn.URN(username); !u.Valid() {
			username = urn.IdamIdentityResource.BuildURN("", username, username).String()
		}

		if cuMail == "" {
			log.Fatal("--mail is mandatory")
		}

		if cuPassword == "" {
			fmt.Printf("Password: ")
			p1, err := gopass.GetPasswd()
			if err != nil {
				log.Fatal(err)
			}

			fmt.Printf("Repeat password: ")
			p2, err := gopass.GetPasswd()
			if err != nil {
				log.Fatal(err)
			}

			if string(p1) != string(p2) {
				log.Fatal("passwords do not match")
			}

			cuPassword = string(p1)
		}

		cli, err := newAdminClient()
		if err != nil {
			log.Fatal(err)
		}
		defer cli.Close()

		identity := idam.Identity{
			Roles: cuRoles,
			Name:  urn.URN(username).AccountID(),
			Type:  idamV1.IdentityType_USER,
			UserData: &idam.UserData{
				FirstName:      cuFirstName,
				LastName:       cuLastName,
				PrimaryMail:    cuMail,
				SecondaryMails: cuSeconaryMails,
			},
		}

		secret, err := cli.CreateIdentity(context.Background(), identity, cuPassword, cuOTP)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("User %s created successfully\n", identity.URN().String())
		if cuOTP {
			fmt.Printf("\nOne-Time-Secret: %s\n", secret)
		}
	},
}

func init() {
	addCmd.AddCommand(createUserCmd)

	createUserCmd.Flags().BoolVar(&cuOTP, "with-2fa", false, "Enable two-factor-authentication")
	createUserCmd.Flags().StringVarP(&cuPassword, "password", "p", "", "Password for the new user account")
	createUserCmd.Flags().StringVar(&cuFirstName, "first-name", "", "First name of the new user")
	createUserCmd.Flags().StringVar(&cuLastName, "last-name", "", "Last name of the new user")
	createUserCmd.Flags().StringVarP(&cuMail, "mail", "m", "", "Mail address for the new user")
	createUserCmd.Flags().StringSliceVarP(&cuRoles, "role", "r", []string{}, "Roles for the new user")
	createUserCmd.Flags().StringSliceVar(&cuSeconaryMails, "with-mail", []string{}, "Additional mail addresses for the user")
}
