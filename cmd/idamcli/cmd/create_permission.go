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

// createPermissionCmd represents the role command
var createPermissionCmd = &cobra.Command{
	Use:     "permission",
	Aliases: []string{"p"},
	Short:   "Create a new permission",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 1 {
			log.Fatal("Missing permission")
		}

		cli, err := newAdminClient()
		if err != nil {
			log.Fatal(err)
		}
		defer cli.Close()

		ui.RunFatal(fmt.Sprintf("Creating permission %q", args[0]), func() error {
			_, err := cli.CreatePermission(context.Background(), args[0])
			return err
		})
	},
}

func init() {
	createCmd.AddCommand(createPermissionCmd)
}
