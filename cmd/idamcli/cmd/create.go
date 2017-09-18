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
	createName           string
	create2FA            bool
	createRoles          []string
	createUser           bool
	createService        bool
	createFirstName      string
	createLastName       string
	createPrimaryMail    string
	createSecondaryMails []string
)

// createCmd represents the create command
var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new identity",
	Run: func(cmd *cobra.Command, args []string) {
		if createUser && createService {
			log.Fatal("only --user or --service can be used")
		}

		if !createService && !createUser {
			log.Fatal("one of --user or --service must be used")
		}

		if !createUser && (createFirstName != "" || createLastName != "" || createPrimaryMail != "" || len(createSecondaryMails) > 0) {
			log.Fatal("--first-name, --last-name, --mail and --extra-mails can only be used with --user")
		}

		if createName == "" {
			log.Fatal("--name is required")
		}

		if createUser && createPrimaryMail == "" {
			log.Fatal("--mail is required for --user")
		}

		var roles []urn.URN

		for _, g := range createRoles {
			u := urn.URN(g)
			if !u.Valid() {
				log.Fatalf("group %s is not valid", g)
			}

			roles = append(roles, u)
		}

		i := idam.Identity{
			Name:  createName,
			Roles: roles,
		}

		if createUser {
			i.Type = idamV1.IdentityType_USER
			i.UserData = &idam.UserData{
				PrimaryMail:    createPrimaryMail,
				SecondaryMails: createSecondaryMails,
				FirstName:      createFirstName,
				LastName:       createLastName,
			}
		} else {
			i.Type = idamV1.IdentityType_SERVICE
		}

		password := ""

		fmt.Printf("Password: ")
		p, err := gopass.GetPasswd()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Confirm: ")
		c, err := gopass.GetPasswd()
		if err != nil {
			log.Fatal(err)
		}

		if string(p) != string(c) {
			log.Fatal("password do not match")
		}

		password = string(p)

		conn, _, _, err := getClient()
		if err != nil {
			log.Fatal(err)
		}
		defer conn.Close()

		cli := idamV1.NewAdminClient(conn)

		res, err := cli.CreateIdentity(context.Background(), &idamV1.CreateIdentityRequest{
			Identity:  i.ToProtobuf(),
			Password:  password,
			Enable2FA: create2FA,
		})
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("User create successfully")

		if create2FA && res.GetTotpSecret() != "" {
			fmt.Printf("OTP-Token: %s\n", res.GetTotpSecret())
		}
	},
}

func init() {
	RootCmd.AddCommand(createCmd)

	createCmd.Flags().StringVar(&createName, "name", "", "Name for the new account")
	createCmd.Flags().BoolVar(&create2FA, "otp", false, "Enable 2-factor-authentication")
	createCmd.Flags().StringSliceVar(&createRoles, "roles", []string{}, "A list of roles the identity belongs to")
	createCmd.Flags().BoolVar(&createUser, "user", false, "Create a new user account")
	createCmd.Flags().BoolVar(&createService, "service", false, "Create a new service account")
	createCmd.Flags().StringVar(&createFirstName, "first-name", "", "First name of the user")
	createCmd.Flags().StringVar(&createLastName, "last-name", "", "Last name of the user")
	createCmd.Flags().StringVar(&createPrimaryMail, "mail", "", "Primary mail address for the user")
	createCmd.Flags().StringSliceVar(&createSecondaryMails, "extra-mails", []string{}, "Additional mail address for the user account")
}
