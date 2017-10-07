package utils

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/fatih/color"
	"github.com/homebot/idam"
	"github.com/homebot/idam/client"
)

type IdentityDetailOpts struct {
	Cli         client.AdminClient
	Roles       bool
	Groups      bool
	Permissions bool
}

func PrintIdentityDetails(i idam.Identity, opts *IdentityDetailOpts) {
	var roles []idam.Role
	var groups []idam.Identity
	var permissions []*idam.Permission

	if opts != nil && opts.Cli != nil {

		if opts.Groups {
			for _, grp := range i.Groups() {
				gi, err := opts.Cli.GetIdentity(context.Background(), grp)
				if err != nil {
					log.Fatal(err)
				}

				groups = append(groups, gi.(*idam.Group))
			}
		}

		if opts.Roles {
			for _, role := range i.Roles() {
				r, err := opts.Cli.GetRole(context.Background(), role)
				if err != nil {
					log.Fatal(err)
				}

				roles = append(roles, *r)
			}
		}

		if opts.Permissions {
			var err error
			_, permissions, err = opts.Cli.GetIdentityPermission(context.Background(), i.AccountName())
			if err != nil {
				log.Fatal(err)
			}
		}

	}

	//
	// Print normal identity details
	//
	name, err := idam.StripIdentityPrefix(i)
	if err != nil {
		name = i.AccountName()
	}

	color.New(color.Bold, color.Underline, color.FgHiWhite).
		Println(name)
	fmt.Println()

	if user, ok := i.(*idam.User); ok {
		fmt.Printf("%s %s\n", user.FirstName, user.LastName)
		fmt.Printf("Mail: %s\n", strings.Join(user.MailAddresses, ", "))
	}

	color.New(color.Bold, color.FgHiWhite).
		Println("\nRoles")

	if len(i.Roles()) == 0 {
		fmt.Println(" <No roles granted>")
	} else if opts.Roles {
		PrintRoleTable(roles)
	} else {
		for _, r := range i.Roles() {
			fmt.Printf(" - %s\n", r)
		}
	}

	color.New(color.Bold, color.FgHiWhite).
		Println("\nGroups")

	if len(i.Groups()) == 0 {
		fmt.Println(" <No group memberships>")
	} else if opts.Groups {
		PrintIdentityTable(groups)
	} else {
		for _, g := range i.Groups() {
			fmt.Printf(" - %s\n", g)
		}
	}

	if opts.Permissions {
		PrintPermissionTable(permissions)
	}
}
