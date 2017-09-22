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

	"github.com/spf13/cobra"
)

// deleteServiceCmd represents the deleteService command
var deleteServiceCmd = &cobra.Command{
	Use:   "service",
	Short: "Delete a service account",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 1 {
			log.Fatal("invalid number of arguments")
		}

		serviceName := args[0]
		if u := urn.URN(serviceName); !u.Valid() {
			serviceName = urn.IdamIdentityResource.BuildURN("", serviceName, serviceName).String()
		}

		cli, err := newAdminClient()
		if err != nil {
			log.Fatal(err)
		}
		defer cli.Close()

		if err := cli.DeleteIdentity(context.Background(), serviceName); err != nil {
			log.Fatal(err)
		}

		fmt.Printf("Service %s deleted\n", serviceName)
	},
}

func init() {
	deleteCmd.AddCommand(deleteServiceCmd)
}
