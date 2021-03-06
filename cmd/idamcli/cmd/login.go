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
	"fmt"

	"github.com/homebot/core/cli"
	"github.com/spf13/cobra"
)

// loginCmd represents the login command
var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Login to IDAM and retrieve a new authentication token",
	Run: func(cmd *cobra.Command, args []string) {
		conn, err := newClient()
		if err == nil {
			defer conn.Close()
		}

		cli.Run(fmt.Sprintf("Authenticating against %s", idamServer), func() error {
			return err
		})
	},
}

func init() {
	RootCmd.AddCommand(loginCmd)
}
