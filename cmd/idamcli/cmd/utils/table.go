package utils

import (
	"os"

	table "github.com/ppacher/go-table"
)

func PrintTable(data []interface{}, columns map[string]ColumnFunc, opt TableOpts) {
	tbl := table.Table{
		Prefix:  " ",
		Spacing: 4,
	}

	// add table header
	var header table.Row
	for _, val := range opt.Columns {
		header = append(header, table.Column{
			Value:     val,
			Underline: true,
		})
	}
	tbl.AddRow(header)

	// add data rows
	for _, i := range data {
		var row table.Row

		for _, val := range opt.Columns {
			row = append(row, columns[val](i))
		}

		tbl.AddRow(row)
	}

	tbl.Write(os.Stdout)
}
