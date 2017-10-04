package cmd

import (
	"context"
	"fmt"
	"log"

	ui "github.com/homebot/core/cli"
	"github.com/spf13/cobra"
)

var addCmd = &cobra.Command{
	Use:     "add",
	Aliases: []string{"a"},
	Short:   "Add roles, groups or permissions",
}

var addRoleToIdentityCmd = &cobra.Command{
	Use:     "role",
	Aliases: []string{"r"},
	Short:   "Add a role to an identity",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 3 {
			log.Fatal("invalid number of parameters")
		}

		roleName := args[0]
		identityType := args[1]
		identityName := args[2]

		switch identityType {
		case "group", "g":
			identityName = "group:" + identityName
		case "user", "u":
			identityName = "user:" + identityName
		default:
			log.Fatal("invalid identity type")
		}

		cli, err := newAdminClient()
		if err != nil {
			log.Fatal(err)
		}
		defer cli.Close()

		ui.RunFatal(fmt.Sprintf("Adding %q to %q", roleName, identityName), func() error {
			return cli.AssignRole(context.Background(), identityName, roleName)
		})
	},
}

var addPermissionToRole = &cobra.Command{
	Use:     "permission",
	Aliases: []string{"p", "perm"},
	Short:   "Add a permission to a role",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 3 {
			log.Fatal("invalid number of parameters")
		}

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
			return cli.AssignPermission(context.Background(), permissionName, roleName)
		})
	},
}

var addGroupToIdentity = &cobra.Command{
	Use:     "group",
	Aliases: []string{"g"},
	Short:   "Add a group to an identity",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 3 {
			log.Fatal("invalid number of parameters")
		}

		groupName := "group:" + args[0]
		identityType := args[1]
		identityName := args[2]

		switch identityType {
		case "group", "g":
			identityName = "group:" + identityName
		case "user", "u":
			identityName = "user:" + identityName
		default:
			log.Fatal("invalid identity type")
		}

		cli, err := newAdminClient()
		if err != nil {
			log.Fatal(err)
		}
		defer cli.Close()

		ui.RunFatal(fmt.Sprintf("Adding %q to %q", identityName, groupName), func() error {
			return cli.AddIdentityToGroup(context.Background(), identityName, groupName)
		})
	},
}

func init() {
	RootCmd.AddCommand(addCmd)

	addCmd.AddCommand(addRoleToIdentityCmd)
	addCmd.AddCommand(addPermissionToRole)
	addCmd.AddCommand(addGroupToIdentity)
}
