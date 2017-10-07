// Copyright © 2017 Patrick Pacher <patrick.pacher@gmail.com>
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
	"github.com/homebot/idam"

	"github.com/spf13/cobra"
)

var (
	cgRoles  []string
	cgGroups []string
)

// createGroupCmd represents the user command
var createGroupCmd = &cobra.Command{
	Use:     "group",
	Aliases: []string{"g"},
	Short:   "Create a new group account",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 1 {
			log.Fatal("invalid number of parameters")
		}

		username := args[0]

		cli, err := newAdminClient()
		if err != nil {
			log.Fatal(err)
		}
		defer cli.Close()

		for idx := range cuGroups {
			cuGroups[idx] = fmt.Sprintf("group:%s", cuGroups[idx])
		}

		identity := idam.NewGroup(fmt.Sprintf("group:%s", username), "", cgRoles, cgGroups, nil)

		var secret string

		ui.Step("Creating groups", func() error {
			ui.Run("Creating identity", func() error {
				var err error
				secret, err = cli.CreateIdentity(context.Background(), identity, "", false)
				return err
			})

			return nil
		})

		fmt.Printf("Group %s created successfully\n", identity.AccountName())
	},
}

func init() {
	createCmd.AddCommand(createGroupCmd)

	createGroupCmd.Flags().StringSliceVarP(&cgRoles, "role", "r", nil, "Roles for the new user")
	createGroupCmd.Flags().StringSliceVarP(&cgGroups, "group", "g", nil, "List of groups memberships for the new user")
}
