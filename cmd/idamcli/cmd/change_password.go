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

	"github.com/howeyc/gopass"

	"github.com/spf13/cobra"
)

// changePasswordCmd represents the changePassword command
var changePasswordCmd = &cobra.Command{
	Use:   "change-password",
	Short: "Change your current password",
	Run: func(cmd *cobra.Command, args []string) {
		cli, err := newClient()
		if err != nil {
			log.Fatal(err)
		}
		defer cli.Close()

		fmt.Printf("Current password: ")
		currentPass, err := gopass.GetPasswd()
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("New password: ")
		newPass1, err := gopass.GetPasswd()
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("New password (repeat): ")
		newPass2, err := gopass.GetPasswd()
		if err != nil {
			log.Fatal(err)
		}

		if string(newPass1) != string(newPass2) {
			log.Fatal("passwords do not match")
		}

		if err := cli.ChangePassword(context.Background(), string(currentPass), string(newPass1)); err != nil {
			log.Fatal(err)
		}

		fmt.Println("Password changed successfully")
	},
}

func init() {
	profileCmd.AddCommand(changePasswordCmd)
}
