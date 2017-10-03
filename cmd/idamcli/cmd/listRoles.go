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
	"github.com/homebot/idam"
	"github.com/spf13/cobra"
)

var (
	listRolesVerbose bool
)

// listCmd represents the list command
var listRolesCmd = &cobra.Command{
	Use:   "roles",
	Short: "Show roles registered at IDAM",
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

		for idx, i := range response {
			fmt.Printf("%d. %s\n", idx, i.Name)
		}
	},
}

func init() {
	listCmd.AddCommand(listRolesCmd)

	listRolesCmd.Flags().BoolVarP(&listRolesVerbose, "verbose", "v", false, "Display detailed information for identities")
}
