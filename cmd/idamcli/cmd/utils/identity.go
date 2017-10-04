package utils

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/homebot/idam"
)

type IdentityDetailOpts struct {
	Roles       bool
	Groups      bool
	Permissions bool
}

func PrintIdentityDetails(i idam.Identity, opts *IdentityDetailOpts) {
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
	} else {
		for _, r := range i.Roles() {
			fmt.Printf(" - %s\n", r)
		}
	}

	color.New(color.Bold, color.FgHiWhite).
		Println("\nGroups")

	if len(i.Groups()) == 0 {
		fmt.Println(" <No group memberships>")
	} else {
		for _, g := range i.Groups() {
			fmt.Printf(" - %s\n", g)
		}
	}
}
