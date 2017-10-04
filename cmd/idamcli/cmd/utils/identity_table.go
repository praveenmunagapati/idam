package utils

import (
	"fmt"
	"time"

	"github.com/fatih/color"
	"github.com/homebot/idam"
	table "github.com/ppacher/go-table"
)

type TableOpts struct {
	// A list of columns to display, defaults to ALL
	Columns []string
}

type ColumnFunc func(x interface{}) table.Column

var IdentityColumns = map[string]ColumnFunc{
	"Name": func(x interface{}) table.Column {
		i := x.(idam.Identity)

		name, err := idam.StripIdentityNamePrefix(i.AccountName())
		if err != nil {
			name = i.AccountName()
		}

		return table.Column{
			Value: name,
			Bold:  true,
		}
	},
	"Type": func(x interface{}) table.Column {
		i := x.(idam.Identity)
		typ := "service"
		var attr []color.Attribute

		switch i.(type) {
		case *idam.User:
			typ = "user"
			attr = []color.Attribute{color.FgHiGreen}
		case *idam.Group:
			typ = "group"
			attr = []color.Attribute{color.FgHiBlue}
		}

		return table.Column{
			Value:      typ,
			Attributes: attr,
		}
	},
	"Groups": func(x interface{}) table.Column {
		i := x.(idam.Identity)

		return table.Column{
			Value: fmt.Sprintf("%d", len(i.Groups())),
		}
	},
	"Roles": func(x interface{}) table.Column {
		i := x.(idam.Identity)

		return table.Column{
			Value: fmt.Sprintf("%d", len(i.Roles())),
		}
	},
	"Creator": func(x interface{}) table.Column {
		return table.Column{
			Value: x.(idam.Identity).Metadata().Creator,
		}
	},
	"Created": func(x interface{}) table.Column {
		return table.Column{
			Value: x.(idam.Identity).Metadata().Created.Format(time.RFC822),
		}
	},
}

func PrintIdentityTable(list []idam.Identity, opts ...TableOpts) {
	if len(opts) > 1 {
		panic("multiple table options are not allowed")
	}

	if len(opts) == 0 {
		opts = append(opts, TableOpts{
			Columns: []string{
				"Name",
				"Type",
				"Groups",
				"Roles",
				"Created",
				"Creator",
			},
		})
	}

	opt := opts[0]

	data := make([]interface{}, len(list))
	for k, v := range list {
		data[k] = v
	}

	PrintTable(data, IdentityColumns, opt)
}
