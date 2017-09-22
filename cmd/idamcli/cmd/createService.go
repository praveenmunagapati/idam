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

	"github.com/homebot/core/urn"
	"github.com/homebot/idam"
	idamV1 "github.com/homebot/protobuf/pkg/api/idam/v1"
	"github.com/howeyc/gopass"

	"github.com/spf13/cobra"
)

var (
	csPassword string
	csRoles    []string
	csOTP      bool
)

// createServiceCmd represents the service command
var createServiceCmd = &cobra.Command{
	Use:   "service",
	Short: "Create a new service account",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 1 {
			log.Fatal("invalid number of arguments")
		}

		serviceName := args[0]
		if u := urn.URN(serviceName); !u.Valid() {
			serviceName = urn.IdamIdentityResource.BuildURN("", serviceName, serviceName).String()
		}

		if csPassword == "" {
			fmt.Printf("Password: ")
			p1, err := gopass.GetPasswd()
			if err != nil {
				log.Fatal(err)
			}

			p2, err := gopass.GetPasswd()
			if err != nil {
				log.Fatal(err)
			}

			if string(p1) != string(p2) {
				log.Fatal("passwords do not match")
			}

			csPassword = string(p1)
		}

		identity := idam.Identity{
			Type:  idamV1.IdentityType_SERVICE,
			Name:  urn.URN(serviceName).AccountID(),
			Roles: csRoles,
		}

		cli, err := newAdminClient()
		if err != nil {
			log.Fatal(err)
		}
		defer cli.Close()

		secret, err := cli.CreateIdentity(context.Background(), identity, csPassword, csOTP)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("Service account created")

		if csOTP {
			fmt.Printf("\nOne-Time-Secret: %s\n", secret)
		}
	},
}

func init() {
	addCmd.AddCommand(createServiceCmd)
	createServiceCmd.Flags().StringVarP(&csPassword, "password", "p", "", "Password for the service account")
	createServiceCmd.Flags().BoolVar(&csOTP, "with-2fa", false, "Enable two-factor-authentication for the service account")
}
