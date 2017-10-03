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
	"os"
	"time"

	"github.com/howeyc/gopass"
	"github.com/mdp/qrterminal"

	ui "github.com/homebot/core/cli"
	"github.com/homebot/idam"

	"github.com/spf13/cobra"
)

var (
	cuPassword      string
	cuOTP           bool
	cuFirstName     string
	cuLastName      string
	cuSeconaryMails []string
	cuRoles         []string
	cuGroups        []string
	cuNoQR          bool
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

		if cuPassword == "" {
			fmt.Printf("Password: ")
			p1, err := gopass.GetPasswd()
			if err != nil {
				ui.Fatalf("", "%s", err)
			}

			fmt.Printf("Repeat password: ")
			p2, err := gopass.GetPasswd()
			if err != nil {
				ui.Fatalf("", "%s, err")
			}

			if string(p1) != string(p2) {
				ui.Fatalf("", "Passwords do not match")
			}

			cuPassword = string(p1)
		}

		cli, err := newAdminClient()
		if err != nil {
			log.Fatal(err)
		}
		defer cli.Close()

		for idx := range cuGroups {
			cuGroups[idx] = fmt.Sprintf("group:%s", cuGroups[idx])
		}

		identity := idam.NewUserIdentity(fmt.Sprintf("user:%s", username), "", cuRoles, cuGroups)
		identity.FirstName = cuFirstName
		identity.LastName = cuLastName
		identity.MailAddresses = cuSeconaryMails

		var secret string

		ui.Step("Creating user", func() error {
			ui.RunFatal("Creating roles ...", func() error {
				<-time.After(time.Second * 1)
				return nil
			})

			ui.RunFatal("Creating identity", func() error {
				var err error
				secret, err = cli.CreateIdentity(context.Background(), identity, cuPassword, cuOTP)
				return err
			})

			return nil
		})

		if cuOTP {
			fmt.Printf("\nOne-Time-Secret: %s\n", secret)

			if !cuNoQR {
				qrterminal.Generate(secret, qrterminal.L, os.Stdout)
			}
		}
	},
}

func init() {
	addCmd.AddCommand(createUserCmd)

	createUserCmd.Flags().BoolVar(&cuOTP, "with-2fa", false, "Enable two-factor-authentication")
	createUserCmd.Flags().StringVarP(&cuPassword, "password", "p", "", "Password for the new user account")
	createUserCmd.Flags().StringVar(&cuFirstName, "first-name", "", "First name of the new user")
	createUserCmd.Flags().StringVar(&cuLastName, "last-name", "", "Last name of the new user")
	createUserCmd.Flags().StringSliceVarP(&cuRoles, "role", "r", []string{}, "Roles for the new user")
	createUserCmd.Flags().StringSliceVar(&cuSeconaryMails, "mail", []string{}, "Additional mail addresses for the user")
	createUserCmd.Flags().StringSliceVarP(&cuGroups, "group", "g", nil, "List of groups memberships for the new user")
	createUserCmd.Flags().BoolVar(&cuNoQR, "no-qr", false, "Don't display the QR code")
}
