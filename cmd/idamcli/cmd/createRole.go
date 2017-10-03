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

var (
	createRolePermissions        []string
	createRoleMissingPermissions bool
)

// createRoleCmd represents the role command
var createRoleCmd = &cobra.Command{
	Use:   "role",
	Short: "Create a new role",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 1 {
			log.Fatal("Missing role name")
		}

		cli, err := newAdminClient()
		if err != nil {
			log.Fatal(err)
		}
		defer cli.Close()

		// TODO: add support to createRoleMissingPermissions
		if createRoleMissingPermissions {
			ui.Fatalf("--create-permissions not yet supported")
		}

		ui.RunFatal(fmt.Sprintf("Creating role %s", args[0]), func() error {
			return cli.CreateRole(context.Background(), args[0], createRolePermissions)
		})
	},
}

func init() {
	addCmd.AddCommand(createRoleCmd)

	createRoleCmd.Flags().StringSliceVarP(&createRolePermissions, "permission", "p", nil, "A list of permissions for the new role")
	createRoleCmd.Flags().BoolVarP(&createRoleMissingPermissions, "create-permissions", "c", false, "Create permissions that does not exist yet")
}
