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

	"github.com/spf13/cobra"
)

// profileCmd represents the profile command
var profileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Manage your profile",
	Run: func(cmd *cobra.Command, args []string) {
		cli, err := newClient()
		if err != nil {
			log.Fatal(err)
		}
		defer cli.Close()

		i, err := cli.GetProfile(context.Background())
		if err != nil {
			log.Fatal(err)
		}

		identityType := "user"

		if i.IsService() {
			identityType = "service"
		}

		fmt.Printf("%s\n", i.URN().String())
		fmt.Printf("\tName: %s\n", i.Name)
		fmt.Printf("\tType: %s\n", identityType)

		if len(i.Roles) > 0 {
			fmt.Printf("\tRoles:\n")
			for _, r := range i.Roles {
				fmt.Printf("\t\t%s\n", r)
			}
		} else {
			fmt.Printf("\tRoles: no roles assigned\n")
		}

		if i.IsUser() && i.UserData != nil {
			if i.UserData.PrimaryMail != "" {
				fmt.Printf("\tMail: %s\n", i.UserData.PrimaryMail)
			}
			if i.UserData.FirstName != "" {
				fmt.Printf("\tFirst-Name: %s\n", i.UserData.FirstName)
			}
			if i.UserData.LastName != "" {
				fmt.Printf("\tLast-Name: %s\n", i.UserData.LastName)
			}
			if len(i.UserData.SecondaryMails) > 0 {
				fmt.Printf("\tAdditional-Mail-Addresses:\n")

				for _, m := range i.UserData.SecondaryMails {
					fmt.Printf("\t\t%s\n", m)
				}
			}
		}
	},
}

func init() {
	RootCmd.AddCommand(profileCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// profileCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// profileCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}