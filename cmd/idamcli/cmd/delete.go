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
	"github.com/spf13/cobra"
)

// deleteCmd represents the delete command
var deleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a role, user or service account",
}

// deleteGroupCmd represents the deleteGroup command
var deleteGroupCmd = &cobra.Command{
	Use:   "group",
	Short: "Delete a group account or remove a membership",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 3 {
			groupName := "group:" + args[0]
			identityType := args[1]
			identityName := args[2]

			switch identityType {
			case "user":
				identityName = "user:" + identityName
			case "group":
				identityName = "group:" + identityName
			default:
				log.Fatal("Invalid identity type")
			}

			cli, err := newAdminClient()
			if err != nil {
				log.Fatal(err)
			}
			defer cli.Close()

			ui.RunFatal(fmt.Sprintf("Deleting %q from %q", identityName, groupName), func() error {
				return cli.DeleteIdentityFromGroup(context.Background(), identityName, groupName)
			})

			return
		}

		if len(args) != 1 {
			log.Fatal("invalid number of arguments")
		}

		username := fmt.Sprintf("group:%s", args[0])

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

var deleteRoleCmd = &cobra.Command{
	Use:   "role",
	Short: "Delete a role",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 3 {
			roleName := args[0]
			identityType := args[1]
			identityName := args[2]

			switch identityType {
			case "user":
				identityName = "user:" + identityName
			case "group":
				identityName = "group:" + identityName
			default:
				log.Fatal("Invalid identity type")
			}

			cli, err := newAdminClient()
			if err != nil {
				log.Fatal(err)
			}
			defer cli.Close()

			ui.RunFatal(fmt.Sprintf("Deleting %q from %q", roleName, identityName), func() error {
				return cli.UnassignRole(context.Background(), identityName, roleName)
			})

			return
		}

		if len(args) != 1 {
			log.Fatal("invalid number of arguments")
		}

		roleName := args[0]

		cli, err := newAdminClient()
		if err != nil {
			log.Fatal("failed to create client", err)
		}
		defer cli.Close()

		if err := cli.DeleteRole(context.Background(), roleName); err != nil {
			log.Fatal(err)
		}

		fmt.Printf("Role %s deleted\n", roleName)
	},
}

// deleteServiceCmd represents the deleteService command
var deleteServiceCmd = &cobra.Command{
	Use:   "service",
	Short: "Delete a service account",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 1 {
			log.Fatal("invalid number of arguments")
		}

		serviceName := args[0]

		cli, err := newAdminClient()
		if err != nil {
			log.Fatal(err)
		}
		defer cli.Close()

		ui.RunFatal(fmt.Sprintf("Deleting identity %q", serviceName), func() error {
			return cli.DeleteIdentity(context.Background(), serviceName)
		})
	},
}

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

var deletePermissionCmd = &cobra.Command{
	Use:     "permission",
	Aliases: []string{"p"},
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 3 {
			permissionName := args[0]

			if args[1] != "role" {
				log.Fatal("invalid usage")
			}

			roleName := args[2]

			cli, err := newAdminClient()
			if err != nil {
				log.Fatal(err)
			}
			defer cli.Close()

			ui.RunFatal(fmt.Sprintf("Adding %q to %q", permissionName, roleName), func() error {
				return cli.UnassignPermission(context.Background(), permissionName, roleName)
			})
			return
		}
		if len(args) != 1 {
			log.Fatal("invalid number of arguments")
		}

		cli, err := newAdminClient()
		if err != nil {
			log.Fatal(err)
		}
		defer cli.Close()

		ui.RunFatal(fmt.Sprintf("Deleting permission %q", args[0]), func() error {
			return cli.DeletePermission(context.Background(), args[0])
		})
	},
}

func init() {
	RootCmd.AddCommand(deleteCmd)

	deleteCmd.AddCommand(deleteGroupCmd)
	deleteCmd.AddCommand(deleteRoleCmd)
	deleteCmd.AddCommand(deleteServiceCmd)
	deleteCmd.AddCommand(deleteUserCmd)
	deleteCmd.AddCommand(deletePermissionCmd)
}
