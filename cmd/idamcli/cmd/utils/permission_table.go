package utils

import (
	"time"

	"github.com/homebot/idam"
	table "github.com/ppacher/go-table"
)

var PermissionColumns = map[string]ColumnFunc{
	"Name": func(x interface{}) table.Column {
		return table.Column{
			Value: x.(*idam.Permission).Name,
			Bold:  true,
		}
	},
	"Created": func(x interface{}) table.Column {
		return table.Column{
			Value: x.(*idam.Permission).Created.Format(time.RFC822),
		}
	},
	"Creator": func(x interface{}) table.Column {
		return table.Column{
			Value: x.(*idam.Permission).Creator,
		}
	},
}

func PrintPermissionTable(list []*idam.Permission, opts ...TableOpts) {
	if len(opts) > 1 {
		panic("invalid number of table opts")
	}

	if len(opts) == 0 {
		opts = append(opts, TableOpts{
			Columns: []string{
				"Name",
				"Created",
				"Creator",
			},
		})
	}

	data := make([]interface{}, len(list))
	for k, v := range list {
		data[k] = v
	}

	PrintTable(data, PermissionColumns, opts[0])
}
