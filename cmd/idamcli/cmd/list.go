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
	"github.com/homebot/idam/cmd/idamcli/cmd/utils"
	"github.com/spf13/cobra"
)

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"l"},
	Short:   "Show identities, roles and permissions registered at IDAM",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) > 0 {
			log.Fatalf("Unknown type: %s. Use --help", args[0])
		}

		cli, err := newAdminClient()
		if err != nil {
			log.Fatal(err)
		}
		defer cli.Close()

		var identities []idam.Identity
		var roles []idam.Role
		var permissions []*idam.Permission

		ui.Step("Loading data", func() error {
			ui.RunFatal("Loading identities", func() error {
				var err error
				identities, err = cli.LookupIdentities(context.Background())
				return err
			})

			ui.RunFatal("Loading permissions", func() error {
				var err error
				permissions, err = cli.ListPermissions(context.Background())
				return err
			})

			ui.RunFatal("Loading roles", func() error {
				var err error
				roles, err = cli.ListRoles(context.Background())
				return err
			})

			return nil
		})

		ui.Step("Identities", func() error {
			utils.PrintIdentityTable(identities)
			return nil
		})
		ui.Step("Roles", func() error {
			utils.PrintRoleTable(roles)
			return nil
		})
		ui.Step("Permissions", func() error {
			utils.PrintPermissionTable(permissions)
			return nil
		})
	},
}

// listCmd represents the list command
var listIdentitiesCmd = &cobra.Command{
	Use:     "identities",
	Aliases: []string{"i", "identity"},
	Short:   "Show identities registered at IDAM",
	Run: func(cmd *cobra.Command, args []string) {
		cli, err := newAdminClient()
		if err != nil {
			log.Fatal(err)
		}
		defer cli.Close()

		var response []idam.Identity
		ui.RunFatal("Loading identities", func() error {
			var err error
			response, err = cli.LookupIdentities(context.Background())
			return err
		})

		utils.PrintIdentityTable(response)
	},
}

var listGroupsCmd = &cobra.Command{
	Use:     "groups",
	Aliases: []string{"g", "group"},
	Short:   "List groups",
	Run: func(cmd *cobra.Command, args []string) {
		cli, err := newAdminClient()
		if err != nil {
			log.Fatal(err)
		}
		defer cli.Close()

		var response []idam.Identity
		ui.RunFatal("Loading identities", func() error {
			var err error
			response, err = cli.LookupIdentities(context.Background())
			return err
		})

		var groups []idam.Identity

		for _, i := range response {
			if idam.IsGroup(i) {
				groups = append(groups, i)
			}
		}

		utils.PrintIdentityTable(groups)
	},
}

var listUsersCmd = &cobra.Command{
	Use:     "users",
	Aliases: []string{"u", "user"},
	Short:   "List users",
	Run: func(cmd *cobra.Command, args []string) {
		cli, err := newAdminClient()
		if err != nil {
			log.Fatal(err)
		}
		defer cli.Close()

		var response []idam.Identity
		ui.RunFatal("Loading identities", func() error {
			var err error
			response, err = cli.LookupIdentities(context.Background())
			return err
		})

		var users []idam.Identity

		for _, i := range response {
			if idam.IsUser(i) {
				users = append(users, i)
			}
		}

		utils.PrintIdentityTable(users)
	},
}

// listCmd represents the list command
var listPermissionsCmd = &cobra.Command{
	Use:     "permissions",
	Aliases: []string{"p", "permission"},
	Short:   "Show permissions registered at IDAM",
	Run: func(cmd *cobra.Command, args []string) {
		cli, err := newAdminClient()
		if err != nil {
			log.Fatal(err)
		}
		defer cli.Close()

		var response []*idam.Permission
		ui.RunFatal("Loading permissions", func() error {
			var err error
			response, err = cli.ListPermissions(context.Background())
			return err
		})

		fmt.Println()

		utils.PrintPermissionTable(response)
	},
}

// listCmd represents the list command
var listRolesCmd = &cobra.Command{
	Use:     "roles",
	Aliases: []string{"r", "role"},
	Short:   "Show roles registered at IDAM",
	Run: func(cmd *cobra.Command, args []string) {
		cli, err := newAdminClient()
		if err != nil {
			log.Fatal(err)
		}
		defer cli.Close()

		var response []idam.Role
		ui.RunFatal("Loading roles", func() error {
			var err error
			response, err = cli.ListRoles(context.Background())
			return err
		})

		fmt.Println()

		utils.PrintRoleTable(response)
	},
}

func init() {
	RootCmd.AddCommand(listCmd)

	listCmd.AddCommand(listIdentitiesCmd)
	listCmd.AddCommand(listGroupsCmd)
	listCmd.AddCommand(listUsersCmd)
	listCmd.AddCommand(listPermissionsCmd)
	listCmd.AddCommand(listRolesCmd)
}
