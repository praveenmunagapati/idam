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
	color.New(color.Bold, color.Underline, color.FgHiWhite).
		Println(i.AccountName())
	fmt.Println()

	if user, ok := i.(*idam.User); ok {
		fmt.Printf("%s %s\n", user.FirstName, user.LastName)
		fmt.Printf("Mail: %s\n", strings.Join(user.MailAddresses, ", "))
	}
}
