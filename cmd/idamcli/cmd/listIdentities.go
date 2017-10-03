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
	"os"

	"github.com/fatih/color"
	ui "github.com/homebot/core/cli"
	"github.com/homebot/idam"
	table "github.com/ppacher/go-table"
	"github.com/spf13/cobra"
)

var (
	listIdentitiesVerbose bool
)

// listCmd represents the list command
var listIdentitiesCmd = &cobra.Command{
	Use:   "identities",
	Short: "Show identities registered at IDAM",
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

		fmt.Println()

		tb := table.Table{
			Prefix:  " ",
			Spacing: 5,
		}

		tb.AddRow(table.Row{
			table.Column{
				Value:      "Name",
				Attributes: []color.Attribute{color.Underline},
			},
			table.Column{
				Value:      "Type",
				Attributes: []color.Attribute{color.Underline},
			},
			table.Column{
				Value:      "Roles",
				Attributes: []color.Attribute{color.Underline},
			},
			table.Column{
				Value:      "Groups",
				Attributes: []color.Attribute{color.Underline},
			},
		})

		for _, i := range response {
			identityType := "Service"

			if idam.IsUser(i) {
				identityType = "User"
			} else if idam.IsGroup(i) {
				identityType = "Group"
			}

			name, err := idam.StripIdentityNamePrefix(i.AccountName())
			if err != nil {
				log.Printf("%s: %s", i.AccountName(), err)
				name = i.AccountName()
			}

			max := len(i.Groups())
			if len(i.Roles()) > max {
				max = len(i.Roles())
			}

			if max == 0 {
				max = 1
			}

			for idx := 0; idx < max; idx++ {
				var row = table.Row{}

				group := ""
				role := ""

				if idx < len(i.Groups()) {
					name, _ := idam.StripIdentityNamePrefix(i.Groups()[idx])
					group = name
				}
				if idx < len(i.Roles()) {
					role = i.Roles()[idx]
				}

				if idx == 0 {
					var userAttr []color.Attribute

					if i.Disabled() {
						userAttr = append(userAttr, color.FgHiYellow)
						name = name + " (disabled)"
					}

					row = append(row,
						table.Column{
							Value:      name,
							Attributes: userAttr,
							Bold:       true,
						},
						table.Column{
							Value: identityType,
						},
						table.Column{
							Value:      role,
							RightAlign: true,
						},
						table.Column{
							Value:      group,
							RightAlign: true,
						})
				} else {
					row = append(row,
						table.Column{},
						table.Column{},
						table.Column{
							Value: role,
						},
						table.Column{
							Value: group,
						})
				}
				tb.AddRow(row)
			}
		}

		tb.Write(os.Stdout)
	},
}

func init() {
	listCmd.AddCommand(listIdentitiesCmd)

	listIdentitiesCmd.Flags().BoolVarP(&listIdentitiesVerbose, "verbose", "v", false, "Display detailed information for identities")
}
