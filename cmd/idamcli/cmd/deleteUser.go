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

	ui "github.com/homebot/core/cli"
	"github.com/spf13/cobra"
)

// deleteUserCmd represents the deleteUser command
var deleteUserCmd = &cobra.Command{
	Use:   "user",
	Short: "Delete a user account",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 1 {
			log.Fatal("invalid number of arguments")
		}

		username := fmt.Sprintf("user:%s", args[0])

		cli, err := newAdminClient()
		if err != nil {
			log.Fatal(err)
		}
		defer cli.Close()

		ui.RunFatal(fmt.Sprintf("Deleting identity %q", username), func() error {
			return cli.DeleteIdentity(context.Background(), username)
		})

	},
}

func init() {
	deleteCmd.AddCommand(deleteUserCmd)
}
