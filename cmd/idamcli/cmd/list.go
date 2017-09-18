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

	"github.com/homebot/idam"
	idamV1 "github.com/homebot/protobuf/pkg/api/idam/v1"
	"github.com/spf13/cobra"
)

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "Show identities registered at IDAM",
	Run: func(cmd *cobra.Command, args []string) {
		conn, _, _, err := getClient()
		if err != nil {
			log.Fatal(err)
		}
		defer conn.Close()

		cli := idamV1.NewAdminClient(conn)

		response, err := cli.LookupIdentities(context.Background(), &idamV1.LookupRequest{})
		if err != nil {
			log.Fatal(err)
		}

		for _, msg := range response.GetIdentities() {
			i := idam.IdentityFromProto(msg)
			identityType := "User-Account"

			if i.IsService() {
				identityType = "Service-Account"
			}

			fmt.Printf("%s\t%s\t%d groups\n", i.Name, identityType, len(i.Roles))
		}
	},
}

func init() {
	RootCmd.AddCommand(listCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// listCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// listCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
