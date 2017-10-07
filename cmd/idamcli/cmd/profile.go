// Copyright © 2017 Pacher Patrick <patrick.pacher@gmail.com>
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
	"log"

	"github.com/homebot/idam/cmd/idamcli/cmd/utils"
	"github.com/spf13/cobra"
)

// profileCmd represents the profile command
var profileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Manage your profile",
	Run: func(cmd *cobra.Command, args []string) {
		cli, err := newClient()
		if err != nil {
			log.Fatal(err)
		}
		defer cli.Close()

		// Fixme
		adm, err := newAdminClient()
		if err != nil {
			log.Fatal(err)
		}
		defer adm.Close()

		i, err := cli.GetProfile(context.Background())
		if err != nil {
			log.Fatal(err)
		}

		utils.PrintIdentityDetails(i, &utils.IdentityDetailOpts{
			Cli:         adm,
			Roles:       true,
			Groups:      true,
			Permissions: true,
		})
	},
}

func init() {
	RootCmd.AddCommand(profileCmd)
}
