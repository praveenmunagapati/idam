package utils

import (
	"fmt"
	"time"

	"github.com/homebot/idam"
	table "github.com/ppacher/go-table"
)

var RoleColumns = map[string]ColumnFunc{
	"Name": func(x interface{}) table.Column {
		return table.Column{
			Value: x.(idam.Role).Name,
			Bold:  true,
		}
	},
	"Permissions": func(x interface{}) table.Column {
		return table.Column{
			Value: fmt.Sprintf("%d", len(x.(idam.Role).Permissions)),
		}
	},
	"Created": func(x interface{}) table.Column {
		return table.Column{
			Value: x.(idam.Role).Created.Format(time.RFC822),
		}
	},
	"Creator": func(x interface{}) table.Column {
		return table.Column{
			Value: x.(idam.Role).Creator,
		}
	},
}

func PrintRoleTable(roles []idam.Role, opts ...TableOpts) {
	if len(opts) > 1 {
		panic("only one TableOpts may be specified")
	}

	if len(opts) == 0 {
		opts = append(opts, TableOpts{
			Columns: []string{
				"Name",
				"Permissions",
				"Created",
				"Creator",
			},
		})
	}

	data := make([]interface{}, len(roles))
	for k, v := range roles {
		data[k] = v
	}

	PrintTable(data, RoleColumns, opts[0])
}
